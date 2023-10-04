/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/* rfc6698.txt */

#ifndef RDATA_GENERIC_PQTLSA_61440_C
#define RDATA_GENERIC_PQTLSA_61440_C

#define RRTYPE_PQTLSA_ATTRIBUTES 0

static isc_result_t
generic_fromtext_pqtlsa(ARGS_FROMTEXT) {
	isc_token_t token;

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(origin);
	UNUSED(options);
	UNUSED(callbacks);

	/*
	 * total packet length., 15(f)*16+15(f)=255, one-octec value
	 */
	//RETRR = 함수의 실행결과가 error면 반환 아니면 끝, Return Err
	//isc_tokentype_number=2
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 0xffU) {
		//RETTOK, Return Token, ISC_R_RANGE 41
		RETTOK(ISC_R_RANGE);
	}
	RETERR(uint8_tobuffer(token.value.as_ulong, target));

	/*
	 * current packet length.
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 0xffU) {
		RETTOK(ISC_R_RANGE);
	}
	RETERR(uint8_tobuffer(token.value.as_ulong, target));

	/*
	 * Matching type.
	
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 0xffU) {
		RETTOK(ISC_R_RANGE);
	}
	RETERR(uint8_tobuffer(token.value.as_ulong, target));
 	*/

	/*
	 * Certificate Association Data. lexer로 16진수데이터를 2진데이터로 변환해서 target에 저장하고, -2(입력데이터의 끝까지)저장
	 */
	return (isc_hex_tobuffer(lexer, target, -2));
}

static isc_result_t
generic_totext_pqtlsa(ARGS_TOTEXT) {
	isc_region_t sr;
	char buf[sizeof("64000 ")];
	unsigned int n;

	REQUIRE(rdata->length != 0);

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &sr);

	/*
	 * total packet length.
	 */
	n = uint8_fromregion(&sr); //8비트 읽어옴
	isc_region_consume(&sr, 1); //1바이트 읽고, 데이터 제거
	snprintf(buf, sizeof(buf), "%u ", n); //버퍼에저장
	RETERR(str_totext(buf, target)); //버퍼에있는걸 타겟에 추가

	/*
	 * current packet length.
	 */
	n = uint8_fromregion(&sr);
	isc_region_consume(&sr, 1);
	snprintf(buf, sizeof(buf), "%u ", n);
	RETERR(str_totext(buf, target));


	/*
	 * Certificate Association Data., 플래그 확인하여 괄호로 묶어주는 작업
	 */
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0) {
		RETERR(str_totext(" (", target));
	}
	RETERR(str_totext(tctx->linebreak, target));

	//데이터를 16진수 텍스트로 변화하여 target에 저장하는 함수를 호출 tctx->width가 0이면 한번에 출력하고 아니면 tctx->width-2로 출력
	if (tctx->width == 0) { /* No splitting */
		RETERR(isc_hex_totext(&sr, 0, "", target));
	} else {
		RETERR(isc_hex_totext(&sr, tctx->width - 2, tctx->linebreak,
				      target));
	}
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0) {
		RETERR(str_totext(" )", target));
	}
	return (ISC_R_SUCCESS);
}


//이진 데이터에서 파싱하여 메모리 버퍼로 읽어옴
static isc_result_t
generic_fromwire_pqtlsa(ARGS_FROMWIRE) {
	isc_region_t sr;

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(dctx);

	isc_buffer_activeregion(source, &sr);

	/* Total(1), Current(1), Data(1+) */
	//길이가 3보다 작으면 반환
	if (sr.length < 3) {
		return (ISC_R_UNEXPECTEDEND);
	}

	isc_buffer_forward(source, sr.length);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static isc_result_t
 //텍스트 형식의 DNS 레코드 정보를 메모리 구조로 변환
fromtext_pqtlsa(ARGS_FROMTEXT) {
	//pqTLSA 레코드의 데이터 형식인지 확인
	REQUIRE(type == dns_rdatatype_pqtlsa);
	return (generic_fromtext_pqtlsa(CALL_FROMTEXT));
}

//메모리에 있는 DNS 레코드 정보를 텍스트로 표현
static isc_result_t
totext_pqtlsa(ARGS_TOTEXT) {
	REQUIRE(rdata->type == dns_rdatatype_pqtlsa);

	return (generic_totext_pqtlsa(CALL_TOTEXT));
}

//이진 데이터에서 메모리구조로 변환
static isc_result_t
fromwire_pqtlsa(ARGS_FROMWIRE) {
	REQUIRE(type == dns_rdatatype_pqtlsa);

	return (generic_fromwire_pqtlsa(CALL_FROMWIRE));
}

static isc_result_t
towire_pqtlsa(ARGS_TOWIRE) {
	isc_region_t sr;
	//타입확인, 길이가 0이 아닌지 확인
	REQUIRE(rdata->type == dns_rdatatype_pqtlsa);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);
	//rdata 구조체에서 데이터를 읽어와서 sr에 포인터
	dns_rdata_toregion(rdata, &sr);
	//메모리에 있는걸 버퍼(target)로 저장
	return (mem_tobuffer(target, sr.base, sr.length));
}

static int
compare_pqtlsa(ARGS_COMPARE) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type); //레코드타입
	REQUIRE(rdata1->rdclass == rdata2->rdclass); //클래스
	REQUIRE(rdata1->type == dns_rdatatype_pqtlsa); //첫번째 레코드의 타입
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (isc_region_compare(&r1, &r2));
}
//이진데이터로 변환해서 버퍼에 저장
static isc_result_t
generic_fromstruct_pqtlsa(ARGS_FROMSTRUCT) {
	dns_rdata_pqtlsa_t *pqtlsa = source;
	REQUIRE(pqtlsa != NULL);
	REQUIRE(pqtlsa->common.rdtype == type);
	REQUIRE(pqtlsa->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(uint8_tobuffer(pqtlsa->total_packet_length, target));
	RETERR(uint8_tobuffer(pqtlsa->current_packet_length, target));
	//data도 타켓버퍼에 저장
	return (mem_tobuffer(target, pqtlsa->data, pqtlsa->length));
}

static isc_result_t
generic_tostruct_pqtlsa(ARGS_TOSTRUCT) {
	dns_rdata_pqtlsa_t *pqtlsa = target;
	isc_region_t region;

	REQUIRE(pqtlsa != NULL);
	REQUIRE(rdata->length != 0);

	REQUIRE(pqtlsa != NULL);
	REQUIRE(pqtlsa->common.rdclass == rdata->rdclass);
	REQUIRE(pqtlsa->common.rdtype == rdata->type);
	REQUIRE(!ISC_LINK_LINKED(&pqtlsa->common, link));

	dns_rdata_toregion(rdata, &region);

	pqtlsa->total_packet_length = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	pqtlsa->current_packet_length = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	pqtlsa->length = region.length;

	pqtlsa->data = mem_maybedup(mctx, region.base, region.length);
	pqtlsa->mctx = mctx;
	return (ISC_R_SUCCESS);
}

static void
generic_freestruct_pqtlsa(ARGS_FREESTRUCT) {
	dns_rdata_pqtlsa_t *pqtlsa = source;

	REQUIRE(pqtlsa != NULL);

	if (pqtlsa->mctx == NULL) {
		return;
	}

	if (pqtlsa->data != NULL) {
		isc_mem_free(pqtlsa->mctx, pqtlsa->data);
	}
	pqtlsa->mctx = NULL;
}

static isc_result_t
fromstruct_pqtlsa(ARGS_FROMSTRUCT) {
	REQUIRE(type == dns_rdatatype_pqtlsa);

	return (generic_fromstruct_pqtlsa(CALL_FROMSTRUCT));
}

static isc_result_t
tostruct_pqtlsa(ARGS_TOSTRUCT) {
	dns_rdata_pqtlsa_t *pqtlsa = target;

	REQUIRE(rdata->type == dns_rdatatype_pqtlsa);
	REQUIRE(pqtlsa != NULL);

	pqtlsa->common.rdclass = rdata->rdclass;
	pqtlsa->common.rdtype = rdata->type;
	ISC_LINK_INIT(&pqtlsa->common, link);

	return (generic_tostruct_pqtlsa(CALL_TOSTRUCT));
}

static void
freestruct_pqtlsa(ARGS_FREESTRUCT) {
	dns_rdata_pqtlsa_t *pqtlsa = source;

	REQUIRE(pqtlsa != NULL);
	REQUIRE(pqtlsa->common.rdtype == dns_rdatatype_pqtlsa);

	generic_freestruct_pqtlsa(source);
}

static isc_result_t
additionaldata_pqtlsa(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_pqtlsa);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(add);
	UNUSED(arg);

	return (ISC_R_SUCCESS);
}

static isc_result_t
digest_pqtlsa(ARGS_DIGEST) {
	isc_region_t r;

	REQUIRE(rdata->type == dns_rdatatype_pqtlsa);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

static bool
checkowner_pqtlsa(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_pqtlsa);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return (true);
}

static bool
checknames_pqtlsa(ARGS_CHECKNAMES) {
	REQUIRE(rdata->type == dns_rdatatype_pqtlsa);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	return (true);
}

static int
casecompare_pqtlsa(ARGS_COMPARE) {
	return (compare_pqtlsa(rdata1, rdata2));
}

#endif /* RDATA_GENERIC_pqTLSA_52_C */
