#define _GNU_SOURCE
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include <libconfig.h>
#include <glib.h>

#include "common.h"
#include "list.h"
#include "config.h"
#include "action.h"
#include "subst.h"
#include "uevent.h"
#include "util.h"

struct exec_action {
	struct action base;
	const char *path;
	int argc;
	struct subst_vec **argv;
	int envc;
	const char **envp;
	uid_t uid;
	gid_t gid;
};

static inline struct exec_action *
to_exec_action(const struct action *base_action)
{
	return container_of(base_action, struct exec_action, base);
}


static int
setup_argv(const struct exec_action *action, const config_setting_t *command,
	   struct subst_vec ***vecp, int *countp)
{
	int ret, i;
	gint argc;
	gchar **argv = NULL;
	GError *error = NULL;
	const char *args;
	struct subst_vec **vec;

	if (!config_setting_require_string(command))
		return -EINVAL;

	args = config_setting_get_string(command);

	*vecp = NULL;
	*countp = 0;

	if (g_shell_parse_argv(args, &argc, &argv, &error) != TRUE) {
		g_assert(error->code != G_SHELL_ERROR_EMPTY_STRING);
		config_error(command, "%s", error->message);
		return -EINVAL;
	}

	vec = calloc(argc + 1, sizeof(*vec));
	if (!vec) {
		ret = -ENOMEM;
		goto free;
	}

	for (i = 0; i < argc; i++) {
		ret = subst_tokenize(argv[i], &vec[i]);
		if (ret)
			goto free;
	}
	*countp = argc;
	*vecp = vec;
	return 0;

free:
	for (i = 1; i <= argc; i++) {
		if (vec[i])
			free(vec[i]);
	}
	if (vec)
		free(vec);
	if (argv)
		g_strfreev(argv);
	return ret;
}

static struct action *
setup(const struct action_type *type, const config_setting_t *setting)
{
	struct exec_action *action;
	const config_setting_t *command, *env;
	const config_setting_t *uid, *gid;
	int ret;

	action = zalloc(sizeof(*action));
	if (!action) {
		log_err("failed to alloc memory for exec action.");
		return NULL;
	}
	action_init(&action->base, setting, type);

	command = config_setting_get_member(setting, "command");
	env = config_setting_get_member(setting, "env");
	uid = config_setting_get_member(setting, "uid");
	gid = config_setting_get_member(setting, "gid");

	if (!command) {
		config_error(setting, "action type `exec' requires `command'.");
		goto free;
	}

	ret = setup_argv(action, command,
			 &action->argv, &action->argc);
	if (ret)
		goto free;

	if (env) {
		int count, i;
		if (config_setting_type(env) == CONFIG_TYPE_STRING)
			count = 1;
		else if (config_setting_is_aggregate(env))
			count = config_setting_length(env);
		else {
			config_error(env, "`env' must be string or aggregate of strings, formatted as key=value (value may be empty).");
			goto free;
		}

		action->envp = calloc(count + 1, sizeof(char *));
		if (!action->envp)
			goto free;

		ret = config_setting_fill_string_vector(action->envp + 1,
							count, env);
		if (ret) {
			g_assert(ret != -ERANGE);
			goto free;
		}
		action->envp[count] = NULL;

		for (i = 1; action->envp[i]; i++) {
			if (!strchr(action->envp[i], '=')) {
				config_error(env, "`%s' is not a valid environment value.  Must be key=value (value may be empty).",
						     action->envp[i]);
			}
		}
	}

	if (uid) {
		if (config_setting_type(uid) == CONFIG_TYPE_STRING) {
			const char *user = config_setting_get_string(uid);
			ret = util_get_user(user, &action->uid, &action->gid);
			if (ret == -ENOENT) {
				config_error(uid,
				     "Failed to look up user %s: No such user.",
				      user);
				goto free;
			} else if (ret) {
				config_error(uid,
					     "Failed to look up user `%s'",
					     user);
				goto free;
			}
		} else if (!config_setting_require_int(uid)) {
			action->uid = config_setting_get_int(uid);
			/*
			 * We need to grab the primary group for this user
			 * in case it's not overridden in the config
			 */
			if (!gid) {
				ret = util_get_user_by_uid(action->uid, NULL,
							   &action->gid);
				if (ret == -ENOENT) {
					config_error(uid,
					     "Failed to look up uid %u: No such user.",
					      uid);
					goto free;
				} else if (ret) {
					config_error(uid,
					     "Failed to look up uid %u",
					      uid);
					goto free;
				}
			}
		} else
			goto free;
	}

	if (gid) {
		if (config_setting_type(gid) == CONFIG_TYPE_STRING) {
			const char *grname;
			int ret;

			grname = config_setting_get_string(gid);
			ret = util_get_group(grname, &action->gid);
			if (ret == -ENOENT) {
				config_error(gid,
					     "Failed to look up group `%s': No such group.",
					     grname);
				goto free;
			} else if (ret) {
				config_error(gid,
					     "Failed to look up group `%s': %s",
					     grname, strerror(errno));
				goto free;
			}
		} else if (!config_setting_require_int(gid))
			action->gid = config_setting_get_int(gid);
		else
			goto free;
	}

	return &action->base;

free:
	action_release(&action->base);
	return NULL;
}

static int
execute(const struct action *base_action, struct udev_device *uevent)
{
	const struct exec_action *action = to_exec_action(base_action);
	int ret = 0, i;
	pid_t pid = 0;

	g_assert(action != NULL);
	g_assert(uevent != NULL);

	if (!global_state.dry_run)
		pid = fork();
	if (pid == 0) { /* child */
		const char **args;
		char *env[1] = { NULL };
		char **envp = env;

		if (action->envp)
			envp = (char **)action->envp;

		args = alloca(sizeof(char *) * (action->argc + 1));
		for (i = 0; i < action->argc; i++) {
			args[i] = uevent_subst(action->argv[i], uevent);
			if (!args[i]) {
				errno = EINVAL;
				goto no_exec;
			}
		}
		args[action->argc] = NULL;

		ret = util_set_cred(action->gid, action->uid);
		if (ret)
			goto no_exec;

		if (global_state.debug || global_state.dry_run) {
			char *cmdline = util_strjoin(args, " ");
			if (global_state.dry_run)
				log_info("Would start child for \"%s\"\n",
					 cmdline);
			else
				log_debug("Starting child %u: %s",
					  getpid(), cmdline);
			free(cmdline);
			if (global_state.dry_run)
				return 0;
		}

		ret = execvpe(args[0], (char ** const)args, envp);
		if (ret) {
			log_warn("failed to execute %s: %s",
				 args[0], strerror(errno));
no_exec:
			_exit(1);
		}

		/* Not reached */
	} else if (pid > 0) { /* parent */
		return util_wait_helper(pid);
	} else {
		ret = -errno;
		log_err("fork failed: %s", strerror(errno));
	}

	return ret;
}

static void
release(struct action *base_action)
{
	struct exec_action *action = to_exec_action(base_action);

	if (action->argv)
		free(action->argv);
	if (action->envp)
		free(action->envp);
	free(action);
}

struct action_type exec_action_type = {
	.name = "exec",
	.setup = setup,
	.execute = execute,
	.release = release,
};
