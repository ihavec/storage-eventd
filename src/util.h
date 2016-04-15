#ifndef _UTIL_H_
#define _UTIL_H_
#include <sys/types.h>
#include <sys/wait.h>

int util_wait_helper(pid_t pid);
void util_drop_priv(void);
int util_set_cred(uid_t uid, gid_t gid);
int util_setup_unpriv(const char *user, const char *group);
int util_get_user(const char *user, uid_t *uid, gid_t *gid);
int util_get_user_by_uid(uid_t uid, const char **user, gid_t *gid);
int util_get_group(const char *group, gid_t *gid);

void util_blkid_open(void);
const char *util_blkid_get_dev_by_uuid(const char *uuid);
const char *util_blkid_get_devno_tag(dev_t devno, const char *tag);
const char *util_blkid_get_devno_fstype(dev_t devno);
const char *util_blkid_get_devno_uuid(dev_t devno);

const char *util_get_any_mountpoint_devno(dev_t devno);

char * util_strjoin(const char *args[], char *sep);
#endif /* _UTIL_H_ */
