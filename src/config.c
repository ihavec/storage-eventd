#define _GNU_SOURCE
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <libconfig.h>
#include <glib.h>
#include <blkid.h>

#include "common.h"
#include "list.h"
#include "action.h"
#include "filter.h"
#include "config.h"
#include "util.h"
#include "subst.h"

static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t config_cond = PTHREAD_COND_INITIALIZER;

struct config_context
{
	config_t config;
	int refcnt;

	struct list_head filters;
	struct list_head events;
	struct list_head actions;
};

static inline struct config_context *
to_config_context(config_t *config)
{
	return container_of(config, struct config_context, config);
}

static void
event_init(struct event *event, config_setting_t *setting)
{
	event->name = config_setting_name(setting);
	event->setting = setting;
	INIT_LIST_HEAD(&event->node);
}

config_t *
config_alloc(void)
{
	struct config_context *ctx;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		error("Couldn't allocate config context");

	config_init(&ctx->config);
	ctx->refcnt = 1;
	INIT_LIST_HEAD(&ctx->filters);
	INIT_LIST_HEAD(&ctx->actions);
	INIT_LIST_HEAD(&ctx->events);

	return &ctx->config;
}

static void
config_release(config_t *config)
{
	struct config_context *ctx = to_config_context(config);
	struct action *action, *tmp;

	ASSERT(ctx->refcnt == 0);
	config_destroy(&ctx->config);
	list_for_each_entry_safe(action, tmp, &ctx->actions, node) {
		free(action);
	}
	free(ctx);
}
config_t *active_config;

config_t *
config_get(void)
{
	struct config_context *ctx;

	pthread_mutex_lock(&config_mutex);
	ASSERT(active_config != NULL);
	ctx = to_config_context(active_config);
	ASSERT(ctx->refcnt >= 1);
	ctx->refcnt++;
	pthread_mutex_unlock(&config_mutex);

	return &ctx->config;
}

void
config_put(config_t *config)
{
	struct config_context *ctx;
	bool release = false;

	ASSERT(config != NULL);

	ctx = to_config_context(config);
	pthread_mutex_lock(&config_mutex);
	ASSERT(ctx->refcnt > 0);
	if (--ctx->refcnt == 0) {
		ASSERT(&ctx->config != active_config);
		release = true;
	}
	pthread_mutex_unlock(&config_mutex);

	if (release)
		config_release(config);
}

/* Caller passes the reference */
config_t *
config_activate(config_t *config)
{
	config_t *old;

	ASSERT(config != NULL);

	pthread_mutex_lock(&config_mutex);
	old = active_config;
	active_config = config;
	pthread_mutex_unlock(&config_mutex);

	return old;
}

void
config_wait_for_signal(int (*callback)(void))
{
//	int lockstate;
	pthread_mutex_lock(&config_mutex);
	pthread_cond_wait(&config_cond, &config_mutex);
	pthread_mutex_unlock(&config_mutex);
	callback();
}

void
config_signal(void)
{
	pthread_cond_broadcast(&config_cond);
}

const char *
config_setting_source_basename(const config_setting_t *setting)
{
	return basename(config_setting_source_file(setting));
}

bool
config_setting_require_string(const config_setting_t *setting)
{
	if (config_setting_type(setting) != CONFIG_TYPE_STRING) {
		config_error(setting, "`%s' must be a quoted string.",
			     config_setting_name(setting));
		return false;
	}
	return true;
}

bool
config_setting_require_int(const config_setting_t *setting)
{
	if (config_setting_type(setting) != CONFIG_TYPE_INT) {
		config_error(setting,
			     "`%s' must be an integer in the range(%d,%d).",
			     config_setting_name(setting),
			     -1L << ((sizeof(int) << 3) - 1),
			      1L << ((sizeof(int) << 3) - 1));
		return false;
	}
	return true;
}

bool
config_setting_require_int64(const config_setting_t *setting)
{
	if (config_setting_type(setting) != CONFIG_TYPE_INT64) {
		config_error(setting,
			     "`%s' must be an integer in the range(%lld,%lld).",
			     config_setting_name(setting),
			     -1LL << ((sizeof(long long) << 3) - 1),
			      1LL << ((sizeof(long long) << 3) - 1));
		return false;
	}
	return true;
}

int
config_setting_fill_string_vector(const char **vector, size_t len,
				  const config_setting_t *setting)
{
	int i, count;

	g_assert(len > 0);

	if (config_setting_type(setting) == CONFIG_TYPE_STRING) {
		vector[0] = config_setting_get_string(setting);
		return 1;
	}

	count = config_setting_length(setting);
	if (count > len)
		return -ERANGE;

	for (i = 0; i < count; i++) {
		config_setting_t *value;
		value = config_setting_get_elem(setting, i);

		if (!config_setting_require_string(value))
			return -EINVAL;

		vector[i] = config_setting_get_string(value);
	}

	return 0;
}

int config_for_each_event(config_t *config, event_callback callback,
			  struct udev_device *uevent)
{
	struct config_context *cxt = to_config_context(config);
	struct event *event;
	int ret;
	int count = 0;

	list_for_each_entry(event, &cxt->events, node) {
		ret = callback(config, event, uevent);
		if (!ret)
			count++;
		if (ret == -ESRCH)
			ret = 0;
		if (ret)
			break;
	}

	if (ret)
		return ret;
	return count;
}

static int
parse_config(config_t *config)
{
	struct config_context *ctx = to_config_context(config);
	config_setting_t *events, *actions, *filters;
	struct action *action;
	bool fail = false;
	int i, count;
	struct event *event;

	actions = config_lookup(config, "actions");
	if (actions) {
		count = config_setting_length(actions);
		for (i = 0; i < count; i++) {
			config_setting_t *group;

			group = config_setting_get_elem(actions, i);
			action = action_setup(group);
			if (!action)
				return -1;

			list_add_tail(&action->node, &ctx->actions);
		}
	}

	action = action_make_ignore();
	if (!action)
		return -1;
	list_add_tail(&action->node, &ctx->actions);

	filters = config_lookup(config, "filters");
	if (filters) {
		count = config_setting_length(filters);
		for (i = 0; i < count; i++) {
			config_setting_t *group;
			struct filter *filter;

			group = config_setting_get_elem(filters, i);
			filter = filter_setup(group);
			if (!filter)
				return -1;
			list_add_tail(&filter->node, &ctx->filters);
		}
	}

	events = config_lookup(config, "events");
	if (!config_setting_is_group(events)) {
		log_err("events must be a group.");
		return -1;
	}

	count = config_setting_length(events);
	for (i = 0; i < count; i++) {
		config_setting_t *group;
		config_setting_t *filter, *action;
		int filter_count = 1;
		int filter_type;
		int action_count = 1;
		int action_type;
		int a;

		group = config_setting_get_elem(events, i);
		filter = config_setting_get_member(group, "filter");
		action = config_setting_get_member(group, "action");

		if (!action) {
			config_error(group, "event requires `action'.");
			fail = true;
		}

		if (fail)
			return -1;

		event = zalloc(sizeof(*event));
		if (!event)
			return -1;
		event_init(event, group);

		action_type = config_setting_type(action);
		if (action_type == CONFIG_TYPE_LIST)
			action_count = config_setting_length(action);
		else if (action_type != CONFIG_TYPE_STRING &&
			 action_type != CONFIG_TYPE_GROUP) {
			config_error(action, "`action' must be action name, group defining new action, or list consisting of a combination of either.");
			goto fail;
		}

		event->actions = calloc(action_count, sizeof(*event->actions));
		if (!event->actions)
			goto fail;
		event->num_actions = action_count;

		for (a = 0; a < action_count; a++) {
			config_setting_t *elem = action;
			int atype = action_type;
			if (action_type == CONFIG_TYPE_LIST) {
				elem = config_setting_get_elem(action, a);
				atype = config_setting_type(elem);
			}

			if (atype == CONFIG_TYPE_GROUP)
				event->actions[a] = action_setup(elem);
			else if (atype == CONFIG_TYPE_STRING)
				event->actions[a] = action_lookup(&ctx->actions,
								  elem);
			else {
				config_error(elem, "`action' list element must be action name or group defining new action.");
				goto fail;
			}
		}

		if (filter) {
			filter_type = config_setting_type(filter);
			if (filter_type == CONFIG_TYPE_LIST)
				filter_count = config_setting_length(filter);
			else if (filter_type != CONFIG_TYPE_STRING &&
				 filter_type != CONFIG_TYPE_GROUP) {
				config_error(filter, "`filter' must be filter name, group defining new filter, or list consisting of a combination of either.");
				goto fail;
			}

			event->filters = calloc(filter_count, sizeof(*event->filters));
			if (!event->filters)
				goto fail;
			event->num_filters = filter_count;

			for (a = 0; a < filter_count; a++) {
				config_setting_t *elem = filter;
				int atype = filter_type;
				if (filter_type == CONFIG_TYPE_LIST) {
					elem = config_setting_get_elem(filter, a);
					atype = config_setting_type(elem);
				}

				if (atype == CONFIG_TYPE_GROUP)
					event->filters[a] = filter_setup(elem);
				else if (atype == CONFIG_TYPE_STRING)
					event->filters[a] = filter_lookup(&ctx->filters,
									  elem);
				else {
					config_error(elem, "`filter' list element must be filter name or group defining new filter.");
					goto fail;
				}
			}
		}

		list_add_tail(&event->node, &ctx->events);
	}

	return 0;

fail:
	if (event->filters)
		free(event->filters);
	if (event->actions)
		free(event->actions);
	if (event)
		free(event);
	return -1;
}

int
reload_config(void)
{
	config_t *config, *old;
	FILE *file;
	int err;
	bool drop_priv = false;

	if (global_state.exiting)
		return 0;

	config = config_alloc();
	if (!config) {
		log_err("config_alloc failed: %s", strerror(errno));
		return -1;
	}

	if (access(global_state.config_file, R_OK) != 0) {
		/* We don't bail on error - the fopen will fail for us */
		err = util_set_cred(0, 0);
		if (!err)
			drop_priv = true;
	}

	file = fopen(global_state.config_file, "r");
	if (!file) {
		log_err("Could not open config file `%s': %s",
			global_state.config_file, strerror(errno));
		if (drop_priv)
			util_drop_priv();

		config_put(config);
		return -1;
	}

	if (drop_priv)
		util_drop_priv();

	err = config_read_file(config, global_state.config_file);
	fclose(file);
	if (err == CONFIG_FALSE) {
		log_err("Reading config file `%s' failed: %s; line %d",
			global_state.config_file, config_error_text(config),
			config_error_line(config));
		config_put(config);
		return -1;
	}

	err = parse_config(config);
	if (err) {
		log_err("Error while parsing configuration.  Not reloading.");
		config_put(config);
		return -1;
	}

	old = config_activate(config);
	log_debug("Activated new config.");
	if (old)
		config_put(old);

	return 0;
}

int event_action(const struct event *event, struct udev_device *uevent)
{
	int ret = 0;
	int i;
	for (i = 0; i < event->num_actions; i++) {

		/* Nonzero return stops execution but isn't an error. */
		ret = action_execute(event->actions[i], uevent);
		if (ret)
			break;
	}
	if (ret < 0)
		log_err("Failed to execute %d actions.",
			event->num_actions - i);
	return ret;
}

bool event_filter(const struct event *event, struct udev_device *uevent)
{
	int i;

	if (!event->num_filters) {
		log_debug("Matched event on NULL filter");
		return true;
	}

	for (i = 0; i < event->num_filters; i++) {
		if (filter_execute(event->filters[i], uevent)) {
			log_debug("Matched event on filter %s",
				  event->filters[i]->name);
			return true;
		} else {
			log_debug("Did not match event on filter %s",
				event->filters[i]->name);
		}
	}
	return false;
}

const char *
config_lookup_fn(const char *key, void *unused, bool *needs_free)
{
	*needs_free = false;
	if (!strcmp(key, "HOSTNAME"))
		return global_state.hostname;
	return NULL;
}

const char *config_var_subst(const struct subst_vec *vec)
{
	return subst_replace(vec, config_lookup_fn, NULL);
}
