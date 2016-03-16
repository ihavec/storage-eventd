#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

int
log_msg(int level, const char *fmt, ...)
{
	va_list args;

	if (level == LOG_DEBUG)
		return 0;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
	return 0;
}
