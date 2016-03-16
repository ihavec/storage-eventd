#define _GNU_SOURCE
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>

#include <libconfig.h>
#include <glib.h>

#include "common.h"
#include "list.h"
#include "action.h"
#include "config.h"
#include "subst.h"
#include "uevent.h"
#include "util.h"

#define DEFAULT_SENDER "Storage Event Daemon on ${HOSTNAME} <root>"
#define DEFAULT_SENDMAIL_PATH "/usr/sbin/sendmail"
#define DEFAULT_SUBJECT "Storage Event Notification"

#ifdef DEBUG
#define DEFAULT_TEMPLATE_FILE BASEDIR "/src/email-template.txt"
#else
#define DEFAULT_TEMPLATE_FILE "/etc/storage-eventd/email-template.txt"
#endif

struct email_action {
	struct action base;
	const char *sendmail_path;
	struct subst_vec *sender;
	struct subst_vec *subject;
	char *template_buf;
	struct subst_vec *email_template;
	int recipient_count;
	const char *recipients[0];
};

static inline struct email_action *
to_email_action(const struct action *base_action)
{
	return container_of(base_action, struct email_action, base);
}

static struct action *
setup(const struct action_type *type, const config_setting_t *setting)
{
	struct email_action *action;
	const config_setting_t *sender, *subject, *recipients, *template;
	const config_setting_t *sendmail;
	int rcount = 0;
	int ret;
	int recipients_type;
	const char *template_file = DEFAULT_TEMPLATE_FILE;
	struct stat st;
	FILE *fp;

	recipients = config_setting_get_member(setting, "recipients");
	sender = config_setting_get_member(setting, "sender");
	subject = config_setting_get_member(setting, "subject");
	template = config_setting_get_member(setting, "template");
	sendmail = config_setting_get_member(setting, "sendmail");

	if (!recipients) {
		config_error(setting, "action type `email' requires `recipients' as string or list.");
		return NULL;
	}

	if (sender && !config_setting_require_string(sender))
		return NULL;

	if (subject && !config_setting_require_string(subject))
		return NULL;

	if (sendmail && !config_setting_require_string(sendmail))
		return NULL;

	if (template && !config_setting_require_string(template))
		return NULL;

	if (template)
		template_file = config_setting_get_string(template);
	else
		template = setting; /* for error printing */


	recipients_type = config_setting_type(recipients);
	if (recipients_type == CONFIG_TYPE_STRING)
		rcount = 1;
	else if (recipients_type == CONFIG_TYPE_LIST)
		rcount = config_setting_length(recipients);
	else {
		config_error(recipients, "`recipients' must be quoted string or list of quoted strings");
		return NULL;
	}

	action = zalloc(sizeof(*action) + sizeof(char *) * rcount);
	action_init(&action->base, setting, type);
	action->recipient_count = rcount;

	if (sender) {
		ret = subst_tokenize(config_setting_get_string(sender),
				     &action->sender);
		if (ret) {
			config_error(sender,
				     "Could not tokenize subject for variable substitution.");
			goto fail;
		}
	} else {
		ret = subst_tokenize(DEFAULT_SENDER, &action->sender);
		if (ret) {
			config_error(setting,
				     "Could not tokenize default sender for variable substitution.[BUG].");
			goto fail;
		}
	}

	if (subject) {
		ret = subst_tokenize(config_setting_get_string(subject),
				     &action->subject);
		if (ret) {
			config_error(subject,
				     "Could not tokenize subject for variable substitution.");
			goto fail;
		}
	} else {
		ret = subst_tokenize(DEFAULT_SUBJECT, &action->subject);
		if (ret) {
			config_error(setting,
				     "Could not tokenize default subject for variable substitution.[BUG].");
			goto fail;
		}
	}

	if (sendmail) {
		action->sendmail_path = config_setting_get_string(sendmail);
		if (access(action->sendmail_path, X_OK)) {
			config_error(sendmail,
				     "Can't execute sendmail helper `%s': %s",
				     action->sendmail_path, strerror(errno));
			goto fail;
		}
	}

	fp = fopen(template_file, "r");
	if (!fp) {
		config_error(template, "Couldn't open template file `%s': %s",
			     template_file, strerror(errno));
		goto fail;
	}

	ret = fstat(fileno(fp), &st);
	if (ret) {
		config_error(template, "Could not stat template file `%s': %s",
			     template_file, strerror(errno));
		goto fail;
	}

	action->template_buf = malloc(st.st_size + 1);
	if (!action->template_buf) {
		config_error(template,
			     "Could not allocate %u bytes for template file.",
			     st.st_size + 1);
		goto fail;
	}

	ret = fread(action->template_buf, 1, st.st_size, fp);
	action->template_buf[st.st_size] = '\0';
	fclose(fp);

	if (ret != st.st_size) {
		log_err("short read %u != %u while reading template file.",
			ret, st.st_size);
		goto fail;
	}

	ret = subst_tokenize(action->template_buf, &action->email_template);
	if (ret) {
		config_error(template,
			     "Could not tokenize email template for variable substitution.");
		goto fail;

	}

	if (config_setting_type(recipients) == CONFIG_TYPE_STRING)
		action->recipients[0] = config_setting_get_string(recipients);
	else {
		ret = config_setting_fill_string_vector(action->recipients,
							rcount, recipients);
		g_assert(ret != -ERANGE);
		if (ret)
			goto fail;
	}

	return &action->base;
fail:
	action_release(&action->base);
	return NULL;
}

static int
print_email(const struct email_action *action, struct udev_device *uevent,
	    FILE *fp, const char *sender, const char *recipient, time_t now)
{
	int ret = -1;
	const char *subject = NULL, *body = NULL;

	subject = uevent_subst(action->subject, uevent);
	if (!subject)
		goto out;

	body = uevent_subst(action->email_template, uevent);
	if (!body)
		goto out;

	ret = 0;
	fprintf(fp, "From: %s\n", sender);
	fprintf(fp, "To: %s\n", recipient);
	fprintf(fp, "Date: %s", asctime(localtime(&now)));
	fprintf(fp, "Subject: %s\n", subject);
	fprintf(fp, "\n");
	fprintf(fp, "%s\n\n", body);
	fprintf(fp, ".\n");

out:
	if (subject)
		free((char *)subject);
	if (body)
		free((char *)body);

	return ret;
}

static int
execute(const struct action *base_action, struct udev_device *uevent)
{
	struct email_action *action = to_email_action(base_action);
	g_assert(action != NULL);
	g_assert(uevent != NULL);
	const char *sender;
	const char *sendmail = action->sendmail_path;
	time_t ts = time(NULL);
	int ret = 0;
	int i;

	if (!sendmail)
		sendmail = DEFAULT_SENDMAIL_PATH;

	sender = config_var_subst(action->sender);
	if (!sender)
		return -1;

	for (i = 0; i < action->recipient_count; i++) {
		int pipes[2];
		int ret;
		FILE *fp = stderr;
		const char *recip = action->recipients[i];
		pid_t pid;

		if (global_state.dry_run) {
			log_info("Sending email to %s", recip);
			fprintf(stderr, "------\n");
			ret = print_email(action, uevent, fp,
					  sender, recip, ts);
			fprintf(stderr, "------\n");
			continue;
		}

		ret = pipe(pipes);
		if (ret < 0) {
			log_err("Failed to create pipe for sendmail.");
			break;
		}

		pid = fork();
		if (pid == 0) {
			close(STDIN_FILENO);
			close(pipes[1]);
			ret = dup2(pipes[0], STDIN_FILENO);
			if (ret) {
				log_err("Failed to connect pipe to stdin: %s",
					strerror(errno));
				_exit(1);
			}

			log_info("Child %u for sendmail", getpid());
			ret = execl(sendmail, sendmail, "-f", sender, recip,
				    NULL);
			if (ret) {
				log_err("exec failed: %s", strerror(errno));
				_exit(1);
			}

			/* Not reached */
		} else if (pid > 0) { /* parent */
			close(pipes[0]);
			fp = fdopen(pipes[1], "w");
			if (!fp)
				log_err("Couldn't open FILE API for pipe.");
			else {
				ret = print_email(action, uevent, fp,
						  sender, recip, ts);
				fclose(fp);
				if (ret)
					log_err("print email failed.");
			}
			return util_wait_helper(pid);
		} else {
			ret = -errno;
			log_err("fork failed: %s", strerror(errno));
		}
	}
	free((char *)sender);
	return ret;
}

static void
release(struct action *base_action)
{
	struct email_action *action = to_email_action(base_action);

	if (action->subject)
		subst_release(action->subject);
	if (action->email_template)
		subst_release(action->email_template);
	if (action->template_buf)
		free(action->template_buf);
	free(action);
}

struct action_type email_action_type = {
	.name = "email",
	.setup = setup,
	.execute = execute,
	.release = release,
};
