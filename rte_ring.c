/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2010-2015 Intel Corporation
 * Copyright (c) 2007,2008 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/queue.h>

#include "rte_ring.h"

/* true if x is a power of 2 */
#define POWEROF2(x) ((((x)-1) & (x)) == 0)

/**
 * Macro to align a value to a given power-of-two. The resultant value
 * will be of the same type as the first parameter, and will be no
 * bigger than the first parameter. Second parameter must be a
 * power-of-two value.
 */
#define RTE_ALIGN_FLOOR(val, align) \
	(typeof(val))((val) & (~((typeof(val))((align) - 1))))

/**
 * Macro to align a value to a given power-of-two. The resultant value
 * will be of the same type as the first parameter, and will be no lower
 * than the first parameter. Second parameter must be a power-of-two
 * value.
 */
#define RTE_ALIGN_CEIL(val, align) \
	RTE_ALIGN_FLOOR(((val) + ((typeof(val)) (align) - 1)), align)

/**
 * Macro to align a value to a given power-of-two. The resultant
 * value will be of the same type as the first parameter, and
 * will be no lower than the first parameter. Second parameter
 * must be a power-of-two value.
 * This function is the same as RTE_ALIGN_CEIL
 */
#define RTE_ALIGN(val, align) RTE_ALIGN_CEIL(val, align)

static inline size_t
strlcpy(char *dst, const char *src, size_t size)
{
    return (size_t)snprintf(dst, size, "%s", src);
}

static inline uint32_t
rte_combine32ms1b(uint32_t x)
{
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;

    return x;
}

static inline uint32_t
rte_align32pow2(uint32_t x)
{
    x--;
    x = rte_combine32ms1b(x);

    return x + 1;
}

/* return the size of memory occupied by a ring */
ssize_t
rte_ring_get_memsize(unsigned count)
{
	ssize_t sz;

	/* count must be a power of 2 */
	if ((!POWEROF2(count)) || (count > RTE_RING_SZ_MASK )) {
		printf("Requested size is invalid, must be power of 2, and "
			"do not exceed the size limit %u\n", RTE_RING_SZ_MASK);
		return -EINVAL;
	}

	sz = sizeof(struct rte_ring) + count * sizeof(void *);
	sz = RTE_ALIGN(sz, RTE_CACHE_LINE_SIZE);
	return sz;
}

void
rte_ring_reset(struct rte_ring *r)
{
	r->prod.head = r->cons.head = 0;
	r->prod.tail = r->cons.tail = 0;
}

int
rte_ring_init(struct rte_ring *r, const char *name, unsigned count,
	unsigned flags)
{
	int ret;

    //modify by haolipeng
	/* compilation-time checks */
	/*RTE_BUILD_BUG_ON((sizeof(struct rte_ring) &
			  RTE_CACHE_LINE_MASK) != 0);
	RTE_BUILD_BUG_ON((offsetof(struct rte_ring, cons) &
			  RTE_CACHE_LINE_MASK) != 0);
	RTE_BUILD_BUG_ON((offsetof(struct rte_ring, prod) &
			  RTE_CACHE_LINE_MASK) != 0);*/

	/* init the ring structure */
	memset(r, 0, sizeof(*r));
	ret = strlcpy(r->name, name, sizeof(r->name));
	if (ret < 0 || ret >= (int)sizeof(r->name))
		return -ENAMETOOLONG;
	r->flags = flags;
	r->prod.single = (flags & RING_F_SP_ENQ) ? __IS_SP : __IS_MP;
	r->cons.single = (flags & RING_F_SC_DEQ) ? __IS_SC : __IS_MC;

	if (flags & RING_F_EXACT_SZ) {
		r->size = rte_align32pow2(count + 1);
		r->mask = r->size - 1;
		r->capacity = count;
	} else {
		if ((!POWEROF2(count)) || (count > RTE_RING_SZ_MASK)) {
			printf("Requested size is invalid, must be power of 2, and not exceed the size limit %u\n",
				RTE_RING_SZ_MASK);
			return -EINVAL;
		}
		r->size = count;
		r->mask = count - 1;
		r->capacity = r->mask;
	}
	r->prod.head = r->cons.head = 0;
	r->prod.tail = r->cons.tail = 0;

	return 0;
}

/* create the ring */
struct rte_ring *
rte_ring_create(const char *name, unsigned count,
		unsigned flags)
{
	char mz_name[RTE_MEMZONE_NAMESIZE];
	struct rte_ring *r;
	ssize_t ring_size;
	const unsigned int requested_count = count;
	int ret;

	/* for an exact size ring, round up from count to a power of two */
	if (flags & RING_F_EXACT_SZ)
		count = rte_align32pow2(count + 1);

	ring_size = rte_ring_get_memsize(count);
	if (ring_size < 0) {
		return NULL;
	}

	ret = snprintf(mz_name, sizeof(mz_name), "%s%s",
		RTE_RING_MZ_PREFIX, name);
	if (ret < 0 || ret >= (int)sizeof(mz_name)) {
		return NULL;
	}

    ///////////////////modify begin////////////////////////////
	r = (struct rte_ring*)malloc(ring_size);
    if(NULL == r){
        return NULL;
    }
    rte_ring_init(r,name,requested_count,flags);
    ///////////////////modify end////////////////////////////
	return r;
}

/* free the ring */
void
rte_ring_free(struct rte_ring *r)
{
	if (r == NULL)
		return;

	free(r);
}

/* dump the status of the ring on the console */
void
rte_ring_dump(FILE *f, const struct rte_ring *r)
{
	fprintf(f, "ring <%s>@%p\n", r->name, r);
	fprintf(f, "  flags=%x\n", r->flags);
	fprintf(f, "  size=%"PRIu32"\n", r->size);
	fprintf(f, "  capacity=%"PRIu32"\n", r->capacity);
	fprintf(f, "  ct=%"PRIu32"\n", r->cons.tail);
	fprintf(f, "  ch=%"PRIu32"\n", r->cons.head);
	fprintf(f, "  pt=%"PRIu32"\n", r->prod.tail);
	fprintf(f, "  ph=%"PRIu32"\n", r->prod.head);
	fprintf(f, "  used=%u\n", rte_ring_count(r));
	fprintf(f, "  avail=%u\n", rte_ring_free_count(r));
}