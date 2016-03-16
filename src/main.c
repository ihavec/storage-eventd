#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <glib.h>
#include <libconfig.h>

#include "common.h"
#include "config.h"
#include "uevent.h"
#include "util.h"

#define DEFAULT_UNPRIV_USER "nobody"

#ifdef DEBUG
#define DEFAULT_CONFIG_FILE BASEDIR "/src/example.conf"
#else
#define DEFAULT_CONFIG_FILE "/etc/storage-eventd.conf"
#endif

struct global_state global_state = {
	.config_file = DEFAULT_CONFIG_FILE,
};

static void
sighup(int signum)
{
	config_signal();
}

static const char *
signame(int signum)
{
	const char *name;
	switch (signum) {
	case SIGQUIT:
		name = "SIGQUIT";
		break;
	case SIGINT:
		name = "SIGINT";
		break;
	case SIGTERM:
		name = "SIGTERM";
		break;
	default:
		name = "<unknown signo (bug)>";
		break;
	};
	return name;
}

static char origcwd[PATH_MAX + 1];
static void
sigsegv(int signum)
{
	int ret = chdir(origcwd);
	if (ret)
		goto kill;
kill:	signal(signum, SIG_DFL);
	kill(getpid(), signum);
}

static void
sigexit(int signum)
{
	log_info("Received sig on pid %p.  Shutting down.", signame(signum));
	global_state.exiting = true;
	config_signal();
}

static void
usage(void)
{
	fprintf(stderr,
"usage: storage-eventd [OPTIONS]\n\
Options:\n\
  -f, --foreground	    Stay in the foreground; Do not daemonize.\n\
  -d, --debug		    Enable debugging mode; Additional output.\n\
  			    Implies -f.\n\
  -v, --verbose		    Increased verbosity.  Can be specified\n\
  			    multiple times.\n\
  -c, --config config_file  Load a config file other than the default (%s).\n\
  -n, --dry-run		    Listen for events but only print actions that would\n\
  			    be performed instead of executing them.\n\
  -u, --user		    Unprivileged user to use for normal execution.\n\
  			    (default=`%s')\n\
  -g, --group		    Unprivileged group to use for normal execution.\n\
  			    (default=<default group for user>)\n\
  -p, --pidfile		    File in which to write the pid of the main process.\n\
  -h, --help		    Print this message.\n\
\n", DEFAULT_CONFIG_FILE, DEFAULT_UNPRIV_USER);
}

static struct option options[] = {
	{"debug", no_argument, NULL, 'd' },
	{"foreground", no_argument, NULL, 'f' },
	{"verbose", no_argument, NULL, 'v' },
	{"config", required_argument, NULL, 'c' },
	{"dry-run", no_argument, NULL, 'n' },
	{"help", no_argument, NULL, 'h' },
	{"user", required_argument, NULL, 'u', },
	{"group", required_argument, NULL, 'g', },
	{"pidfile", required_argument, NULL, 'p', },
	{}
};

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int arg;
	int err;
	int option_index;
	struct udev_monitor *monitor;
	const char *unpriv_user = DEFAULT_UNPRIV_USER;
	const char *unpriv_group = NULL;
	const char *pidfile = NULL;

	global_state.program_name = basename(argv[0]);

	util_blkid_open();

	if (getcwd(origcwd, sizeof(origcwd))) {
		signal(SIGSEGV, sigsegv);
		signal(SIGQUIT, sigsegv);
	}

	if (chdir("/") < 0) {
		fprintf(stderr, "can't chdir to root directory: %s\n",
			strerror(errno));
		exit(1);
	}

	umask(umask(077) | 022);

	while ((arg = getopt_long(argc, argv, ":dfvc:nu:g:p:",
				  options, &option_index)) != EOF) {
		switch (arg) {
		case 'd':
			global_state.debug = true;
		case 'f':
			global_state.foreground = true;
			break;
		case 'v':
			global_state.verbose++;
			break;
		case 'c':
			global_state.config_file = optarg;
			break;
		case 'n':
			global_state.foreground = true;
			global_state.dry_run = true;
			break;
		case 'u':
			unpriv_user = optarg;
			break;
		case 'g':
			unpriv_group = optarg;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case '?':
		case 'h':
			usage();
			exit(arg == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
		};
	}
	if (optind < argc) {
		usage();
		exit(1);
	}

	if (geteuid() != 0) {
		fprintf(stderr, "need to be root\n");
		exit(1);
	}

	if (!global_state.foreground)
		openlog(global_state.program_name, LOG_PID, LOG_DAEMON);

	err = gethostname(global_state.hostname,
			  sizeof(global_state.hostname));
	if (err)
		goto out;
	global_state.hostname[sizeof(global_state.hostname) - 1] = '\0';

	err = util_setup_unpriv(unpriv_user, unpriv_group);
	if (err)
		goto out;

	log_debug("Loading config.");
	err = reload_config();
	if (err)
		goto out;

	signal(SIGTERM, sigexit);
	signal(SIGINT, sigexit);
	signal(SIGHUP, sighup);

	monitor = uevent_setup_monitor();
	if (!monitor) {
		err = 1;
		goto out;
	}

	log_debug("Starting threads.");

	if (!global_state.foreground) {
		err = daemon(0, 1);
		if (err) {
			perror("daemon");
			goto out;
		}
	}

	if (pidfile) {
		FILE *fp = fopen(pidfile, "w");
		if (!fp) {
			perror(pidfile);
			goto out;
		}
		fprintf(fp, "%u\n", getpid());
		fclose(fp);
	}

	util_drop_priv();

	err = uevent_start_threads(monitor);
	if (err)
		goto out;

	while (!err && !global_state.exiting)
		config_wait_for_signal(reload_config);

	uevent_stop_threads();

out:
	if (!global_state.foreground)
		closelog();

	exit(err ? EXIT_FAILURE : 0);
}
