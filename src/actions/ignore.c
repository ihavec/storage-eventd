#define _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "common.h"
#include "action.h"

static struct action *
action_setup_ignore(const struct action_type *type,
		    const config_setting_t *setting)
{
	struct action *action = zalloc(sizeof(*action));
	if (!action) {
		log_err("failed to alloc memory for ignore action.");
		return NULL;
	}

	__action_init(action, "ignore", type);
	return action;
}

static int
action_do_ignore(const struct action *action, struct udev_device *uevent)
{
	return 1;
}

struct action_type ignore_action_type = {
	.name = "ignore",
	.setup = action_setup_ignore,
	.execute = action_do_ignore,
};
