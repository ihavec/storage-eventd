#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <libconfig.h>

config_t *config_alloc(void);
config_t *config_get(void);
void config_put(config_t *config);
config_t *config_activate(config_t *config);
int reload_config(void);
void config_wait_for_signal(int (*callback)(void));
void config_signal(void);

struct event *event_lookup(struct udev_device *uevent);

const char *config_setting_source_basename(const config_setting_t *setting);
bool config_setting_require_string(const config_setting_t *setting);
bool config_setting_require_int(const config_setting_t *setting);
bool config_setting_require_int64(const config_setting_t *setting);
int config_setting_fill_string_vector(const char **vector, size_t len,
				      const config_setting_t *group);

#define config_error(setting, fmt, args...)				 \
do {									 \
	const config_setting_t *__setting = (setting);			 \
	log_err("%s:%d " fmt, config_setting_source_basename(__setting), \
		config_setting_source_line(__setting), ##args);		 \
} while(0)

struct event {
	const char *name;
	config_setting_t *setting;
	int num_filters;
	const struct filter **filters;
	int num_actions;
	const struct action **actions;
	struct list_head node;
};

struct udev_device;
typedef int (*event_callback)(config_t *, struct event *, struct udev_device *);
int config_for_each_event(config_t *config, event_callback callback,
			  struct udev_device *data);

int event_action(const struct event *event, struct udev_device *uevent);
bool event_filter(const struct event *event, struct udev_device *uevent);

struct subst_vec;
const char *config_lookup_fn(const char *key, void *unused, bool *needs_free);
const char *config_var_subst(const struct subst_vec *vec);

#endif /* _CONFIG_H_ */
