#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "util.h"

int
main(void)
{
	const char *path;

	path = util_get_any_mountpoint_devno(makedev(9, 4));
	printf("path=%s\n", path);
	free((char *)path);

	path = util_get_any_mountpoint_devno(makedev(9, 2));
	printf("path=%s\n", path);
	free((char *)path);
	return 0;
}
