#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <glib.h>
#include <string.h>
#include <stdio.h>

#include "common.h"
#include "subst.h"

static struct subst_vec *
resize_subv(struct subst_vec *vec, int size)
{
	return realloc(vec, sizeof(*vec) + size * sizeof(vec->vec[0]));
}

/*
 * Return the next token structure.  Resize the vector 10 slots at a time.
 * Optimize for the common case and use 2 slots.
 */
static struct subst *
get_sub(struct subst_vec **vecp)
{
	struct subst_vec *vec = *vecp;
	if (!vec) {
		vec = resize_subv(NULL, 2);
		vec->size = 2;
		vec->count = 0;
	} else if (vec->size == vec->count)
		vec = resize_subv(vec, vec->size + 10);

	*vecp = vec;
	return &vec->vec[vec->count++];
}

/*
 * Break up a string into literal and substitition tokens.  The string
 * is not modified or copied and will need to be available for the lifetime
 * of the subst_vec.
 */
int
subst_tokenize(const char *str, struct subst_vec **vecp)
{
	struct subst_vec *subv = NULL;
	struct subst *sub = NULL;
	const char *cur = str;
	int count = 0;
	int deep = 0;

	while (*cur) {
		if (!sub) {
			sub = get_sub(&subv);
			sub->value = cur;
		}
		if (cur[0] == '\\' && cur[1] == '$') {
			cur += 2;
			continue;
		} else if (cur[0] == '$' && cur[1] == '{') {
			if (cur == sub->value) {
				sub->value += 2;
				deep = 1;
			} else if (!deep++) {
				sub->len = cur - sub->value;
				sub->literal = true;
				sub = NULL;
			} else {
				log_err("syntax error at position %u: nested variables are not allowed.",
					cur - str);
				goto fail;
			}
			cur += 2;
			continue;
		} else if (*cur == '}') {
			/*
			 * We actually could handle nested variables but
			 * we don't currently have a way to order them
			 * properly.
			 */
			if (deep > 0) {
				sub->len = cur - sub->value;
				sub->literal = false;
				sub = NULL;
				--deep;
			}
		} else if (*cur == ' ' && deep) {
			log_err("syntax error at position %u: spaces not allowed in variable names.",
				cur - str);
			goto fail;
		}
		cur++;
	}
	if (sub) {
		if (deep) {
			log_err("parse error at end of input: missing closing `}' for variable substitution.");
			goto fail;
		}
		sub->literal = true;
		sub->len = cur - sub->value;
	}

	*vecp = resize_subv(subv, subv->count);

	if (global_state.verbose > 2)
		for (count = 0; count < subv->count; count++) {
			log_debug("subv->vec[%d] = \"%s%.*s\" [%u]", count,
				  subv->vec[count].literal ? "" : "$",
				  subv->vec[count].len,
				  subv->vec[count].value,
				  subv->vec[count].len);
	}

	return 0;

fail:
	subst_release(subv);
	*vecp = NULL;
	return -EINVAL;
}

/*
 * Reconstitute the subst vector as a single string.  The caller is responsible
 * for freeing it.  If a variable can't be found using the lookup routine
 * provided, the string ${VARIABLE} using the variable name will be
 * used instead.
 *
 * All of the allocations except for the final product are done on the stack.
 */
const char *
subst_replace(const struct subst_vec *vec, subst_lookup_fn lookup, void *data)
{
	int i;
	char *ret, *str;
	int len = 0;
	const char *props[vec->count];
	bool needs_free[vec->count];
	int lengths[vec->count];

	/* A string literal */
	if (vec->count == 1 && vec->vec[0].literal) 
		return strndup(vec->vec[0].value, vec->vec[0].len);

	memset(props, 0, sizeof(props));


	for (i = 0; i < vec->count; i++) {
		const char *key;
		if (vec->vec[i].literal) {
			len += vec->vec[i].len;
			continue;
		}
		key = strndupa(vec->vec[i].value, vec->vec[i].len);
		props[i] = lookup(key, data, &needs_free[i]);

		/*
		 * If there's a lookup failure, we output the variable name
		 * as if the specification were a string literal.
		 */
		if (props[i] == NULL) {
			char *buf = alloca(vec->vec[i].len + 4);
			snprintf(buf, vec->vec[i].len + 4, "${%s}", key);
			props[i] = buf;
		}
		lengths[i] = strlen(props[i]);
		len += lengths[i];
	}

	/*
	 * Reassemble the vector as a single string, using the lookups we
	 * just performed.
	 */

	str = ret = malloc(len + 1);
	if (!str)
		return NULL;

	memset(str, 0, len + 1);
	for (i = 0; i < vec->count; i++) {
		if (vec->vec[i].literal) {
			g_assert(vec->vec[i].len <= len);
			strncat(str, vec->vec[i].value, vec->vec[i].len);
			len -= vec->vec[i].len;
		} else {
			g_assert(lengths[i] <= len);
			strncat(str, props[i], lengths[i]);
			len -= lengths[i];
		}
		if (needs_free[i])
			free((char *)props[i]);
	}
	g_assert(len == 0);

	return ret;
}

void
subst_release(struct subst_vec *vec)
{
	free(vec);
}
