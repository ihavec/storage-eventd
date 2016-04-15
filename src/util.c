#include <stdio.h>
#include <linux/btrfs.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <alloca.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <mntent.h>
#include <limits.h>
#include <unistd.h>

#include <blkid.h>
#include <uuid.h>

#define UUID_UNPARSED_SIZE 37

#include "common.h"

int
util_wait_helper(pid_t pid)
{
	int ret;
	int status;

	ret = waitpid(pid, &status, 0);
	if (ret < 0) {
		if (errno != ENOENT) {
			ret = -errno;
			log_warn("waitpid returned %s", strerror(errno));
		} else
			ret = 0;
		return ret;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status))
		log_warn("child %d exited abnormally: exit %d",
			 pid, WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		log_warn("child %d exited abnormally: signal %d",
			 pid, WTERMSIG(status));
	else
		log_debug("child %d exited normally.", pid);

	return 0;
}


int
util_get_user(const char *user, uid_t *uid, gid_t *gid)
{
	struct passwd pwd, *result;
	size_t bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	char *buf;
	int ret;

	if (bufsize < 0)
		return -ERANGE;

	buf = alloca(bufsize);

	ret = getpwnam_r(user, &pwd, buf, bufsize, &result);
	if (ret)
		return -errno;

	if (!result)
		return -ENOENT;

	*uid = result->pw_uid;
	*gid = result->pw_gid;
	return 0;
}

int
util_get_user_by_uid(uid_t uid, const char **user, gid_t *gid)
{
	struct passwd pwd, *result;
	size_t bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	char *buf;
	int ret;

	if (bufsize < 0)
		return -ERANGE;

	buf = alloca(bufsize);

	ret = getpwuid_r(uid, &pwd, buf, bufsize, &result);
	if (ret)
		return -errno;

	if (!result)
		return -ENOENT;

	if (user) {
		*user = strdup(result->pw_name);
		if (!*user)
			return -ENOMEM;
	}
	*gid = result->pw_gid;
	return 0;
}

int
util_get_group(const char *group, gid_t *gid)
{
	struct group grp, *result;
	size_t bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
	char *buf;
	int ret;

	if (bufsize < 0)
		return -ERANGE;

	buf = alloca(bufsize);

	ret = getgrnam_r(group, &grp, buf, bufsize, &result);
	if (ret)
		return -errno;
	if (!result)
		return -ENOENT;

	*gid = result->gr_gid;
	return 0;
}

int
util_setup_unpriv(const char *user, const char *group)
{
	int ret;

	uid_t uid;
	gid_t gid;

	ret = util_get_user(user, &uid, &gid);
	if (ret) {
		if (ret == -ENOENT)
			log_err("Couldn't lookup user `%s': No such user.",
				user);
		else
			log_err("Couldn't lookup user `%s': %s",
				user, strerror(errno));
		return ret;
	}

	if (group) {
		ret = util_get_group(group, &gid);
		if (ret) {
			if (ret == -ENOENT)
				log_err("Couldn't lookup group `%s': No such group",
					group);
			else
				log_err("Couldn't lookup group `%s': %s",
					group, strerror(errno));
			return ret;
		}
	}

	global_state.unpriv_uid = uid;
	global_state.unpriv_gid = gid;

	return 0;
}

void
util_drop_priv(void)
{
	int ret;
	uid_t uid = global_state.unpriv_uid;
	gid_t gid = global_state.unpriv_gid;

	/* Nothing to do */
	if (geteuid() == uid && getgid() == gid)
		return;

	/*
	 * Need to switch back to root since unprivileged users can't
	 * switch to arbitrary users or groups.
	 */
	if (geteuid() != 0 && seteuid(0) != 0) {
		log_err("Couldn't reclaim root privs to switch users: %s",
			strerror(errno));
		goto failure;
	}

	ret = setgroups(1, &gid);
	if (ret) {
		log_err("Couldn't drop privs -- setgroups(1, [%u]) failed: %s",
			gid, strerror(errno));
		goto failure;
	}

	ret = setegid(gid);
	if (ret) {
		log_err("Couldn't drop privs -- setegid(%u) failed: %s",
			gid, strerror(errno));
		goto failure;
	}

	ret = seteuid(uid);
	if (ret) {
		log_err("Couldn't drop privs -- seteuid(%u) failed: %s",
			uid, strerror(errno));
		goto failure;
	}
	return;
failure:
	log_err("FATAL: will not continue with elevated privs");
	exit(EXIT_FAILURE);
}

int
util_set_cred(uid_t uid, gid_t gid)
{
	int ret;

	ret = seteuid(0);
	if (ret) {
		log_err("Couldn't regain root privs -- seteuid(0) failed: %s",
			strerror(errno));
		return ret;
	}

	ret = setegid(gid);
	if (ret) {
		log_err("Couldn't switch group -- setegid(%u)) failed: %s",
			gid, strerror(errno));
		return ret;
	}

	ret = seteuid(uid);
	if (ret) {
		log_err("Couldn't switch effective user -- seteuid(%u) failed: %s",
			uid, strerror(errno));
		return ret;
	}

	return 0;
}

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static blkid_cache cache;

void
util_blkid_open(void)
{
	if (blkid_get_cache(&cache, NULL))
		error("couldn't open blkid cache");
}

const char *util_blkid_get_dev_by_uuid(const char *uuid)
{
	const char *devname = NULL;
	blkid_dev dev;
	pthread_mutex_lock(&mutex);
	dev = blkid_find_dev_with_tag(cache, "uuid", uuid);
	if (dev) {
		devname = blkid_dev_devname(dev);
		if (devname)
			devname = strdup(devname);
	}
	pthread_mutex_unlock(&mutex);
	return devname;
}

const char *util_blkid_get_devno_tag(dev_t devno, const char *tag)
{
	char *devname;
	char *value = NULL;
	pthread_mutex_lock(&mutex);
	devname = blkid_devno_to_devname(devno);
	if (devname) {
		value = blkid_get_tag_value(cache, tag, devname);
		if (value)
			value = strdup(value);
	}
	pthread_mutex_unlock(&mutex);
	return value;
}

const char *util_blkid_get_devno_fstype(dev_t devno)
{
	return util_blkid_get_devno_tag(devno, "TYPE");
}

const char *util_blkid_get_devno_uuid(dev_t devno)
{
	return util_blkid_get_devno_tag(devno, "UUID");
}

#define SCANSPEC "%%*u %%*u %u:%u %%*s %%ms"
const char *
util_get_any_mountpoint_devno(dev_t devno)
{
	char buf[PATH_MAX * 2 + 128]; /* mount point + dev path + stats */
	FILE *fp;
	char *p;
	char *value = NULL;
	char scanspec[sizeof(SCANSPEC) + 4];
	const char *fstype;
	bool is_btrfs;

	fstype = util_blkid_get_devno_fstype(devno);

	is_btrfs = !strcmp(fstype, "btrfs");
	free((char *)fstype);

	/*
	 * btrfs uses an anonymous device, so nothing in
	 * /proc/self/mountinfo will match it.
	 */
	if (is_btrfs) {
		int fd;
		struct mntent mnts, *mnt;
		const char *uuid = util_blkid_get_devno_uuid(devno);
		if (!uuid)
			return NULL;

		fp = setmntent("/proc/self/mounts", "r");

		while ((mnt = getmntent_r(fp, &mnts, buf, sizeof(buf)))) {
			struct btrfs_ioctl_fs_info_args fs_info;
			char btrfs_uuid[UUID_UNPARSED_SIZE];
			int ret;

			if (strcmp(mnt->mnt_type, "btrfs"))
				continue;

			fd = open(mnt->mnt_dir, O_RDONLY|O_DIRECTORY);
			if (fd < 0) {
				log_warn("Couldn't open %s", mnt->mnt_dir);
				continue;
			}
			ret = ioctl(fd, BTRFS_IOC_FS_INFO, &fs_info);
			if (ret < 0) {
				log_warn("ioctl(BTRFS_IOC_FS_INFO) on %s failed: %s",
					 mnt->mnt_dir, strerror(errno));
				continue;
			}

			uuid_unparse(fs_info.fsid, btrfs_uuid);

			if (!memcmp(uuid, btrfs_uuid, sizeof(btrfs_uuid))) {
				if (value)
					free(value);
				value = strdup(mnt->mnt_dir);
				/*
				 * We don't break here because we want
				 * the last one
				 */
			}

			close(fd);
		}

		endmntent(fp);
		return value;
	}

	/*
	 * Scanning /proc/self/mountinfo is faster for devno since we don't
	 * need to stat.
	 */
	snprintf(scanspec, sizeof(scanspec), SCANSPEC,
		 major(devno), minor(devno));
	fp = fopen("/proc/self/mountinfo", "r");
	while ((p = fgets(buf, sizeof(buf), fp)) != NULL) {
		int ret;
		char *path;

		ret = sscanf(p, scanspec, &path);
		if (ret == 1) {
			struct stat st;
			ret = stat(path, &st);
			if (ret || st.st_dev != devno) {
				free(path);
				continue;
			}
			if (value)
				free(value);
			value = path;
		}
	}
	fclose(fp);
	return value;
}

char *
util_strjoin(const char *args[], char *sep)
{
	char *buf, *ptr;
	size_t len  = 0;
	int i;

	for (i = 0; args[i]; i++)
		len += strlen(args[i]) + 2;

	buf = ptr = malloc(len);
	for (i = 0; args[i]; i++) {
		int chars;
		chars = snprintf(ptr, len, "%s%s", i ? sep : "", args[i]);
		ptr += chars;
		len -= chars;
	}
	return buf;
}
