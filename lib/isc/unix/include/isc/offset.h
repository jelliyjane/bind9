/*
 * Copyright (C) 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/* $Id: offset.h,v 1.5 2000/05/25 16:44:25 tale Exp $ */

#ifndef ISC_OFFSET_H
#define ISC_OFFSET_H 1

/*
 * File offsets are operating-system dependent.
 */
#include <limits.h>
#include <sys/types.h>

typedef off_t isc_offset_t;

/*
 * POSIX says "Additionally, blkcnt_t and off_t are extended signed integral
 * types", so the maximum value is all 1s except for the high bit.
 * 1 is sized as an unsigned long long to keep the Solaris 5.6 compiler
 * from complaining about integer overflow from the left shift.
 */
#define ISC_OFFSET_MAXIMUM ((off_t)~(1ULL << (sizeof(off_t) * CHAR_BIT - 1)))

#endif /* ISC_OFFSET_H */
