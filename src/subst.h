#ifndef _SUBST_H_
#define _SUBST_H_
#include <stdbool.h>
#include <sys/types.h>
struct subst {
	bool literal;
	const char *value;
	size_t len;
};

struct subst_vec {
	int size;
	int count;
	struct subst vec[0];
};

typedef const char *(*subst_lookup_fn)(const char *key, void *data,
				      bool *needs_free);

int subst_tokenize(const char *str, struct subst_vec **vecp);
void subst_release(struct subst_vec *vec);
const char *subst_replace(const struct subst_vec *vec, subst_lookup_fn lookup,
			  void *data);
#endif /*_SUBST_H_ */
