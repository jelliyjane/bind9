/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#include <config.h>

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lwres/context.h>
#include <lwres/lwbuffer.h>
#include <lwres/lwres.h>
#include <lwres/lwpacket.h>

static inline void
CHECK(int val, char *msg)
{
	if (val != 0) {
		fprintf(stderr, "%s returned %d\n", msg, val);
		exit(1);
	}
}

static void
hexdump(char *msg, void *base, size_t len)
{
	unsigned char *p;
	unsigned int cnt;

	p = base;
	cnt = 0;

	printf("*** %s (%u bytes @ %p)\n", msg, len, base);

	while (cnt < len) {
		if (cnt % 16 == 0)
			printf("%p: ", p);
		else if (cnt % 8 == 0)
			printf(" |");
		printf(" %02x", *p++);
		cnt++;

		if (cnt % 16 == 0)
			printf("\n");
	}

	if (cnt % 16 != 0)
		printf("\n");
}

static char *TESTSTRING = "This is a test.  This is only a test.  !!!";

int
main(int argc, char *argv[])
{
	int ret;
	lwres_context_t *ctx;
	lwres_lwpacket_t pkt, pkt2;
	lwres_nooprequest_t nooprequest, *nooprequest2;
	lwres_noopresponse_t noopresponse, *noopresponse2;
	lwres_buffer_t b;

	ctx = NULL;
	ret = lwres_context_create(&ctx, NULL, NULL, NULL);
	CHECK(ret, "lwres_context_create");

	pkt.serial = 0x11223344;
	pkt.recvlength = 0x55667788;
	pkt.result = 0;

	nooprequest.datalength = strlen(TESTSTRING);
	nooprequest.data = TESTSTRING;
	ret = lwres_nooprequest_render(ctx, &nooprequest, &pkt, &b);
	CHECK(ret, "lwres_nooprequest_render");

	hexdump("rendered noop request", b.base, b.used);

	/*
	 * Now, parse it into a new structure.
	 */
	lwres_buffer_first(&b);
	ret = lwres_lwpacket_parseheader(&b, &pkt2);
	CHECK(ret, "lwres_lwpacket_parseheader");

	hexdump("parsed pkt2", &pkt2, sizeof(pkt2));

	nooprequest2 = NULL;
	ret = lwres_nooprequest_parse(ctx, &b, &pkt2, &nooprequest2);
	CHECK(ret, "lwres_nooprequest_parse");

	assert(nooprequest.datalength == nooprequest2->datalength);
	assert(memcmp(nooprequest.data, nooprequest2->data,
		       nooprequest.datalength) == 0);

	lwres_nooprequest_free(ctx, &nooprequest2);

	lwres_context_freemem(ctx, b.base, b.length);
	b.base = NULL;
	b.length = 0;

	lwres_context_destroy(&ctx);

	return (0);
}
