#ifndef _ACTION_H_
#define _ACTION_H_

struct action_type;
struct action {
	const char *name;
	const struct action_type *type;
	struct list_head node;
};

typedef struct action *(*action_setup_fn)(const struct action_type *type,
				   const config_setting_t *setting);
typedef int (*action_execute_fn) (const struct action *action,
				  struct udev_device *uevent);
typedef void (*action_release_fn)(struct action *action);

struct action_type {
	const char *name;
	action_setup_fn setup;
	action_execute_fn execute;
	action_release_fn release;
};

void __action_init(struct action *action, const char *name,
		 const struct action_type *type);
void action_init(struct action *action, const config_setting_t *setting,
		 const struct action_type *type);
void action_release(struct action *action);
const struct action *action_lookup(const struct list_head *actions,
				   const config_setting_t *action_name);
struct action *action_setup(const config_setting_t *setting);
struct action *action_make_ignore(void);
int action_execute(const struct action *action, struct udev_device *uevent);


extern struct action_type ignore_action_type;
extern struct action_type email_action_type;
extern struct action_type exec_action_type;

#endif /* _ACTION_H_ */
