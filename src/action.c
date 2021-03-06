#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <libconfig.h>
#include <glib.h>

#include "common.h"
#include "config.h"
#include "list.h"
#include "action.h"

static struct action_type *action_types[] = {
	&exec_action_type,
	&email_action_type,
	&ignore_action_type,
};

void
__action_init(struct action *action, const char *name,
	      const struct action_type *type)
{
	action->name = name;
	action->type = type;
	INIT_LIST_HEAD(&action->node);
	log_debug("adding action: \"%s\"", action->name);
}

void
action_init(struct action *action, const config_setting_t *setting,
	    const struct action_type *type)
{
	const char *name = config_setting_get_nested_name(setting);
	__action_init(action, name, type);
}

void
action_release(struct action *action)
{
	const struct action_type *type = action->type;
	g_assert(list_empty(&action->node));
	free((char *)action->name);
	if (type->release)
		type->release(action);
	else
		free(action);
}

struct action *
action_setup(const config_setting_t *setting)
{
	const char *name;
	config_setting_t *type;
	int i;

	type = config_setting_get_member(setting, "type");
	if (!type) {
		config_error(setting, "action requires `type'.");
		return NULL;
	}

	name = config_setting_require_string(type);
	if (!name)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(action_types); i++) {
		struct action_type *atype = action_types[i];
		if (strcasecmp(atype->name, name))
			continue;
		return atype->setup(atype, setting);
	}

	config_error(type, "Unknown action type `%s'", name);
	return NULL;
}

struct action *
action_make_ignore(void)
{
	struct action *action;
	const char *name;

	action = zalloc(sizeof(*action));
	if (!action) {
		log_err("Failed to setup ignore action: %s", strerror(errno));
		return NULL;
	}

	name = strdup("ignore");
	if (!name) {
		log_err("Failed to allocate memory for action rule name.");
		return NULL;
	}

	__action_init(action, name, &ignore_action_type);
	return action;
}


const struct action *
action_lookup(const struct list_head *actions,
	      const config_setting_t *action_name)
{
	bool found = false;
	const char *name;
	struct action *action;

	name = config_setting_require_string(action_name);
	if (!name)
		return NULL;

	list_for_each_entry(action, actions, node) {
		if (!strcasecmp(action->name, name)) {
			found = true;
			break;
		}
	}

	if (!found) {
		config_error(action_name, "unknown action type `%s'", name);
		return NULL;
	}

	return action;
}

int
action_execute(const struct action *action, struct udev_device *uevent)
{
	log_debug("Executing action %s (%s)", action->name, action->type->name);
	return action->type->execute(action, uevent);
}
