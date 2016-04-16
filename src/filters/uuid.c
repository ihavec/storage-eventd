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

#include "common.h"
#include "filter.h"
#include "config.h"
#include "util.h"

struct uuid_filter {
	struct filter base;
	const char *value;
};

static inline struct uuid_filter *
to_uuid_filter(const struct filter *base_filter)
{
	return container_of(base_filter, struct uuid_filter, base);
}

static struct filter *
setup(const struct filter_type *type, const struct config_setting_t *setting)
{
	const config_setting_t *value;
	struct uuid_filter *filter;

	value = config_setting_get_member(setting, "value");
	if (!value) {
		config_error(setting, "filter type `device' requires `value' as literal string.");
		return NULL;
	}

	filter = zalloc(sizeof(*filter));
	if (!filter) {
		log_err("failed to alloc memory for uuid filter.");
		return NULL;
	}

	filter_init(&filter->base, setting, type);
	filter->value = config_setting_require_string(value);
	if (!filter->value) {
		filter_release(&filter->base);
		return NULL;
	}
	return &filter->base;
}

static bool
execute(const struct filter *filter, struct udev_device *uevent)
{
	int ret;
	bool found = false;
	dev_t devno;
	const char *value = to_uuid_filter(filter)->value;
	const char *devname;

	if (strcmp(udev_device_get_subsystem(uevent), "block"))
		return false;

	devno = udev_device_get_devnum(uevent);

	devname = util_blkid_get_dev_by_uuid(value);
	if (devname) {
		struct stat st;
		ret = stat(devname, &st);
		if (ret == 0)
			found = (devno == st.st_rdev);
		free((char *)devname);
	}

	return found;
}

struct filter_type uuid_filter = {
	.name = "uuid",
	.setup = setup,
	.execute = execute,
};
