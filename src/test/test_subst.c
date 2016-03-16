#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>

#include "common.h"
#include "subst.h"

struct test_case {
	const char *string;
	int expected_ret;
} test_cases[] = {
	{ "${VALUE}", 0 },
	{ "${VA${FOO}LUE}", 0 },
	{ "${VA${FOO}LUE", -EINVAL },
	{ "Test then open variable ${VA${FOO}LUE", -EINVAL },
	{ "${VA${FOO}LUE and more text", -EINVAL },
	{ "Test then open variable ${VA${FOO}LUE and more text", -EINVAL },
	{ "This is a test ${VALUE}", 0 },
	{ "This is a test ${VALUE} with text after", 0 },
	{ "This is a test ${VALUE} with text after and another ${VAR}", 0 },
	{ "This is a test ${VALUE} with text after and another ${VAR} text", 0 },
	{ "This is a test $VALUE} with text after and another ${VAR} text", 0 },
	{ "This is an ${invalid variable}", -EINVAL },
};

static int
test_one(const char *string, int expected_ret)
{
	int ret;
	struct subst_vec *vec = NULL;

	printf("C: \"%s\"\n", string);
	ret = subst_tokenize(string, &vec);

	if (ret == 0) {
		int count;
		for (count = 0; count < vec->count; count++) {
			struct subst *sub = &vec->vec[count];
			printf("%u: %c/\"%.*s\"\n", count,
				sub->literal ? 'L' : 'V',
				sub->len, sub->value);
		}
		subst_release(vec);
	}

	if (ret != expected_ret) {
		printf("test `%s' failed.\n", string);
		printf("---\n");
		return -1;
	}
	printf("---\n");
	return 0;
}

#define DEFAULT_TEMPLATE_FILE BASEDIR "/src/email-template.txt"
int
main(void)
{
	int fd;
	int i;
	char *p;
	struct stat st;
	for (i = 0; i < ARRAY_SIZE(test_cases); i++)
		test_one(test_cases[i].string, test_cases[i].expected_ret);

	fd = open(DEFAULT_TEMPLATE_FILE, O_RDONLY);
	fstat(fd, &st);
	p = malloc(st.st_size + 1);
	read(fd, p, st.st_size);
	p[st.st_size] = 0;
	close(fd);
	test_one(p, 0);

	return 0;
}
