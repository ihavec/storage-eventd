#ifndef _COMMON_H_
#define _COMMON_H_
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <libudev.h>
#include <libconfig.h>

#include "list.h"

#ifndef __noreturn
#define __noreturn      __attribute__((noreturn))
#endif

struct global_state {
	char hostname[128];
	const char *program_name;
	const char *config_file;
	bool foreground;
	bool dry_run;
	bool debug;
	int verbose;
	volatile bool exiting;
	uid_t unpriv_uid;
	gid_t unpriv_gid;
};
extern struct global_state global_state;

void error(const char *fmt, ...) __noreturn;
void assert_failure(const char *file, int line, const char *cond) __noreturn;
void log_msg(int level, const char *fmt, ...);

#define log_err(fmt, args...)		log_msg(LOG_ERR, fmt, ##args)
#define log_warn(fmt, args...)		log_msg(LOG_WARNING, fmt, ##args)
#define log_info(fmt, args...)		log_msg(LOG_INFO, fmt, ##args)
#define log_debug(fmt, args...)		log_msg(LOG_DEBUG, fmt, ##args)

#define ASSERT(condition)					\
do {								\
	if (!(condition))					\
		assert_failure(__FILE__, __LINE__, #condition);	\
} while(0)

static inline void *ERR_PTR(long error)
{
	return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline void *zalloc(size_t size)
{
	return calloc(1, size);
}

#define ARRAY_SIZE(a)	(sizeof(a)/sizeof(a[0]))

#endif /* COMMON_H_ */
