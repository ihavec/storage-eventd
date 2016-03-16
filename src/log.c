#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <pthread.h>

#include "common.h"

static pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;
void
error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	pthread_mutex_lock(&print_lock);
	fprintf(stderr, "%s: ", global_state.program_name);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	pthread_mutex_unlock(&print_lock);
	va_end(ap);
	exit(1);
}

void
log_msg(int level, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	if (true || global_state.foreground) {
		if (level != LOG_DEBUG || global_state.debug) {
			va_list printargs;
			va_copy(printargs, args);
			pthread_mutex_lock(&print_lock);
			fprintf(stderr, "%s: ", global_state.program_name);
			vfprintf(stderr, fmt, printargs);
			fprintf(stderr, "\n");
			pthread_mutex_unlock(&print_lock);
			va_end(printargs);
		}
	}

	if (!global_state.dry_run)
		vsyslog(level, fmt, args);
	va_end(args);
}
