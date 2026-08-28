/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef __APPLE__
#include <malloc/malloc.h>
#define malloc_usable_size(p) malloc_size(p)
#else
#include <malloc.h>
#endif

#define IPA_ALLOC(obj) IPA_ALLOC_N(sizeof(obj))

extern long int ___mem_counter;
extern long int ___mem_peak;

#ifdef MEM_EMIT_DEBUG
#define IPA_ALLOC_N(n) ({ \
	void *___ptr;	  \
	___ptr = malloc(n); \
	___mem_counter += malloc_usable_size(___ptr); \
	if (___mem_counter > ___mem_peak) ___mem_peak = ___mem_counter;	\
	fprintf(stderr, "====> %p=malloc(%zu): %li bytes total, %li bytes peak\n", \
		___ptr, (size_t)n, ___mem_counter, ___mem_peak); \
	assert(___mem_counter >= 0); \
	___ptr; \
})
#else
#define IPA_ALLOC_N(n) malloc(n)
#endif

#ifdef MEM_EMIT_DEBUG
#define IPA_CALLOC(nmemb, n) ({ \
	void *___ptr;	  \
	___ptr = calloc(nmemb, n);		      \
	___mem_counter += malloc_usable_size(___ptr); \
	if (___mem_counter > ___mem_peak) ___mem_peak = ___mem_counter;	\
	fprintf(stderr, "====> %p=calloc(%zu, %ld): %li bytes total, %li bytes peak\n", \
		___ptr, (size_t)nmemb, (long unsigned int)n, ___mem_counter, ___mem_peak); \
	assert(___mem_counter >= 0); \
	___ptr; \
})
#else
#define IPA_CALLOC(nmemb, n) calloc(nmemb, n)
#endif

#ifdef MEM_EMIT_DEBUG
#define IPA_REALLOC(obj, n) ({			\
	void *___ptr;	  \
	/* The trace below reports the old address.  realloc() may free it, and the pointer value is
	 * indeterminate from that moment on, so the address is captured as an integer beforehand and
	 * printed as one.  Casting it back to void * for %p would re-create a pointer into freed
	 * memory, which is what -Wuse-after-free objects to. */ \
	uintptr_t ___old = (uintptr_t)(obj); \
	___mem_counter -= malloc_usable_size(obj); \
	___ptr = realloc(obj, n); \
	___mem_counter += malloc_usable_size(___ptr); \
	if (___mem_counter > ___mem_peak) ___mem_peak = ___mem_counter;	\
	fprintf(stderr, "====> %p=realloc(0x%" PRIxPTR ", %ld): %li bytes total, %li bytes peak\n", \
		___ptr, ___old, (long unsigned int)n, ___mem_counter, ___mem_peak); \
	assert(___mem_counter >= 0); \
	___ptr; \
})
#else
#define IPA_REALLOC(obj, n) realloc(obj, n)
#endif

#ifdef MEM_EMIT_DEBUG
#define IPA_FREE(obj) ({ \
	___mem_counter -= malloc_usable_size(obj); \
	fprintf(stderr, "====> free(%p): %li bytes total, %li bytes peak, %zu bytes freed\n", \
		obj, ___mem_counter, ___mem_peak, malloc_usable_size(obj)); \
	assert(___mem_counter >= 0); \
	free(obj); \
})
#else
#define IPA_FREE(obj) free(obj)
#endif
