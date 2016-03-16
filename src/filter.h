#ifndef _FILTER_H_
#define _FILTER_H_

#include <libconfig.h>
#include "list.h"

struct filter_type;
struct filter {
	const char *name;
	const char *pattern;
	const struct filter_type *type;
	struct list_head node;
};

typedef struct filter *(*filter_setup_fn)(const struct filter_type *filter,
					  const config_setting_t *setting);
typedef bool (*filter_execute_fn)(const struct filter *filter,
				  struct udev_device *uevent);
typedef void (*filter_release_fn)(struct filter *filter);

struct filter_type {
	const char *name;
	filter_setup_fn setup;
	filter_execute_fn execute;
	filter_release_fn release;
};

void
filter_init(struct filter *filter, const config_setting_t *setting,
	    const struct filter_type *type);
const struct filter *filter_lookup(const struct list_head *filters,
				   const config_setting_t *filter_name);
struct filter *filter_setup(const config_setting_t *setting);
bool filter_execute(const struct filter *filter, struct udev_device *uevent);

extern struct filter_type dev_path_filter;
extern struct filter_type uevent_var_filter;
extern struct filter_type uuid_filter;

#endif /* _FILTER_H_ */
