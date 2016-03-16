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
	config_setting_t *parent = config_setting_parent(setting);
	config_setting_t *pparent = config_setting_parent(parent);
	char *name = NULL;
	char buf[4096];

	/* filters section */
	if (config_setting_is_root(pparent))
		name = config_setting_name(setting);
	/* one of a list of inline filters */
	else if (config_setting_type(parent) == CONFIG_TYPE_LIST)
		snprintf(buf, sizeof(buf), "filter_anon_%s_%d",
			 config_setting_name(pparent),
			 config_setting_index(setting));
	else {
		snprintf(buf, sizeof(buf), "filter_anon_%s",
			 config_setting_name(parent));
	}
	filter->name = strdup(name ?: buf);
	log_debug("adding filter: \"%s\"", filter->name);
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

	if (!config_setting_require_string(filter_name))
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

	if (!config_setting_require_string(type))
		return NULL;

	name = config_setting_get_string(type);
	g_assert(name != NULL);

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
