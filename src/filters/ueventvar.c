#define _GNU_SOURCE
#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <regex.h>
#include <stdlib.h>
#include <libudev.h>
#include <glib.h>

#include "filter.h"
#include "config.h"
#include "common.h"

struct ueventvar_filter {
	const char *name;
	const char *value;
	regex_t regex;
	struct filter base;
};

static inline struct ueventvar_filter *
to_ueventvar_filter(const struct filter *base_filter)
{
	return container_of(base_filter, struct ueventvar_filter, base);
}


static struct filter *
setup(const struct filter_type *ftype, const config_setting_t *setting)
{
	const config_setting_t *name, *value;
	struct ueventvar_filter *filter;
	int ret;

	name = config_setting_get_member(setting, "name");
	if (!name) {
		config_error(setting, "filter type `ueventvar' requires `name' as literal string.");
		return NULL;
	}

	if (!config_setting_require_string(name))
		return NULL;

	value = config_setting_get_member(setting, "value");
	if (!value) {
		config_error(setting, "filter type `ueventvar' requires `value' as string describing a regular expression.");
		return NULL;
	}

	if (!config_setting_require_string(value))
		return NULL;

	filter = zalloc(sizeof(*filter));
	filter_init(&filter->base, setting, ftype);
	if (!filter)
		return NULL;

	filter->name = config_setting_get_string(name);
	filter->value = config_setting_get_string(value);

	ret = regcomp(&filter->regex, filter->value, REG_EXTENDED|REG_NOSUB);

	if (ret) {
		char buf[4096];
		regerror(ret, &filter->regex, buf, sizeof(buf));
		config_error(value, "%s", buf);
		free(filter);
	}

	return &filter->base;
}

static bool
execute(const struct filter *base_filter, struct udev_device *uevent)
{
	struct ueventvar_filter *filter = to_ueventvar_filter(base_filter);
	const char *value;
	int ret;

	value = udev_device_get_property_value(uevent, filter->name);
#ifdef DEBUG
	if (!value && !strcmp(filter->name, "SDEV_UA"))
		value = "THIN_PROVISIONING_SOFT_THRESHOLD_REACHED";
#endif
	if (!value)
		return false;

	ret = regexec(&filter->regex, value, 0, NULL, 0);
	return ret == 0;
}

static void
release(struct filter *base_filter)
{
	struct ueventvar_filter *filter = to_ueventvar_filter(base_filter);
	regfree(&filter->regex);
	free(filter);
}

struct filter_type uevent_var_filter = {
	.name = "uevent",
	.setup = setup,
	.execute = execute,
	.release = release,
};
