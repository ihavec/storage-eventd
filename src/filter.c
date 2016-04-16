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

struct filter_type *filter_types[] = {
	&dev_path_filter,
	&uevent_var_filter,
	&uuid_filter,
};

void
filter_init(struct filter *filter, const config_setting_t *setting,
	    const struct filter_type *type)
{
	const char *name = config_setting_get_nested_name(setting);
	log_debug("adding filter: \"%s\"", name);
	filter->name = name;
	filter->type = type;
	INIT_LIST_HEAD(&filter->node);
}

const struct filter *
filter_lookup(const struct list_head *filters,
	      const config_setting_t *filter_name)
{
	bool found = false;
	const char *name;
	struct filter *filter;

	name = config_setting_require_string(filter_name);
	if (!name)
		return NULL;

	name = config_setting_get_string(filter_name);
	g_assert(name != NULL);

	list_for_each_entry(filter, filters, node) {
		if (!strcasecmp(filter->name, name)) {
			found = true;
			break;
		}
	}

	if (!found) {
		config_error(filter_name, "unknown filter type `%s'", name);
		return NULL;
	}

	return filter;
}

void
filter_release(struct filter *filter)
{
	const struct filter_type *type = filter->type;
	g_assert(list_empty(&filter->node));
	free((char *)filter->name);
	if (type->release)
		type->release(filter);
	else
		free(filter);
}

struct filter *
filter_setup(const config_setting_t *setting)
{
	int i;
	const char *name;
	config_setting_t *type;

	type = config_setting_get_member(setting, "type");
	if (!type) {
		config_error(setting, "filter requires `type'.");
		return NULL;
	}

	name = config_setting_require_string(type);
	if (!name)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(filter_types); i++) {
		struct filter_type *ftype = filter_types[i];
		if (strcasecmp(ftype->name, name))
			continue;
		return ftype->setup(ftype, setting);
	}

	config_error(type, "Unknown filter type `%s'", name);
	return NULL;
}

bool
filter_execute(const struct filter *filter, struct udev_device *uevent)
{
	return filter->type->execute(filter, uevent);
}
