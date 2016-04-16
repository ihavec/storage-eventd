#define _GNU_SOURCE
#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <glob.h>
#include <stdlib.h>
#include <libudev.h>
#include <glib.h>

#include "filter.h"
#include "config.h"
#include "common.h"

struct dev_path_filter {
	struct filter base;
	const char *pattern;
};

static inline struct dev_path_filter *
to_dev_path_filter(const struct filter *base_filter)
{
	return container_of(base_filter, struct dev_path_filter, base);
}

static struct filter *
setup(const struct filter_type *type, const struct config_setting_t *setting)
{
	const config_setting_t *pattern;
	struct dev_path_filter *filter;

	pattern = config_setting_get_member(setting, "glob");
	if (!pattern) {
		config_error(setting, "filter type `device' requires `glob' as shell-style glob string.");
		return NULL;
	}

	filter = zalloc(sizeof(*filter));
	if (!filter) {
		log_err("failed to alloc memory for devpath filter");
		return NULL;
	}

	filter_init(&filter->base, setting, type);
	filter->pattern = config_setting_require_string(pattern);
	if (!filter->pattern) {
		filter_release(&filter->base);
		return NULL;
	}
	return &filter->base;
}

static bool
execute(const struct filter *filter, struct udev_device *uevent)
{
	glob_t globbuf;
	int ret;
	int i;
	struct stat st;
	bool found = false;
	dev_t devno;
	const char *pattern = to_dev_path_filter(filter)->pattern;

	if (strcmp(udev_device_get_subsystem(uevent), "block"))
		return false;

	devno = udev_device_get_devnum(uevent);

	ret = glob(pattern, GLOB_NOSORT|GLOB_BRACE, NULL, &globbuf);
	if (ret) {
		if (ret != GLOB_NOMATCH) {
			const char *errtext;
			if (ret == GLOB_NOSPACE)
				errtext = strerror(ENOMEM);
			else if (ret == GLOB_ABORTED)
				errtext = strerror(EIO);
			else if (ret == GLOB_NOMATCH)
				errtext = strerror(ENOENT);
			else
				errtext = strerror(errno);
			log_warn("glob failed for %s with error %d (%s)",
				 pattern, ret, errtext);
		}
		return false;
	}

	for (i = 0; i < globbuf.gl_pathc; i++) {
		const char *filename = globbuf.gl_pathv[i];

		ret = stat(filename, &st);
		if (ret) {
			log_info("could not stat %s: %s",
				 filename, strerror(errno));
			continue;
		}

		log_debug("Comparing to %s %u:%u", filename,
			  major(st.st_rdev), minor(st.st_rdev));
		if (st.st_rdev == devno) {
			found = true;
			break;
		}
	}

	globfree(&globbuf);
	return found;
}

struct filter_type dev_path_filter = {
	.name = "device",
	.setup = setup,
	.execute = execute,
};
