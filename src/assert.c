#include <stdlib.h>
#include <stdio.h>
#include <execinfo.h>
#include "common.h"

void __noreturn
assert_failure(const char *file, int line, const char *cond)
{
	void *stack[200];
	int entries;

	fprintf(stderr, "Assertion failure at %s:%d: %s\n", file, line, cond);
	fflush(stderr);

	entries = backtrace(stack, ARRAY_SIZE(stack));
	backtrace_symbols_fd(stack, entries, fileno(stderr));
	abort();
}
