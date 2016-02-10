/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/auth_ind.c */
/*
 * Copyright (C) 2016 by Red Hat, Inc.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "k5-int.h"
#include <krb5.h>

/*
 * Decode and verify CAMMAC authdata using the svc verifier,
 * and return the contents as an allocated array of authdata pointers.
 */
krb5_error_code
k5_unwrap_cammac_svc(krb5_context context, const krb5_authdata *ad,
                     const krb5_keyblock *key, krb5_authdata ***adata_out)
{
    krb5_data ad_data;
    krb5_error_code ret;
    krb5_cammac *cammac = NULL;

    *adata_out = NULL;

    ad_data = make_data(ad->contents, ad->length);

    ret = decode_krb5_cammac(&ad_data, &cammac);
    if (ret != 0)
        return ret;

    ret = k5_cammac_check_svcver(context, cammac, key);
    if (ret == 0) {
        *adata_out = cammac->elements;
        cammac->elements = NULL;
    }

    k5_free_cammac(context, cammac);
    return ret;
}

/*
 * Decode authentication indicator strings from authdata and return
 * as an allocated array of krb5_data pointers. Successive calls will
 * reallocate and append to the indicators array.
 */
krb5_error_code
k5_authind_decode(const krb5_authdata *ad, krb5_data ***indicators)
{
    krb5_error_code ret = 0;
    krb5_data der_ad, **strdata = NULL, **ai_list = *indicators;
    size_t count, scount;

    if (ad == NULL || ad->ad_type != KRB5_AUTHDATA_AUTH_INDICATOR)
        goto cleanup;

    /* Count existing.  */
    for (count = 0; ai_list != NULL && ai_list[count] != NULL; count++);

    der_ad = make_data(ad->contents, ad->length);
    ret = decode_utf8_strings(&der_ad, &strdata);
    if (ret)
        return ret;

    /* Count new.  */
    for (scount = 0; strdata != NULL && strdata[scount] != NULL; scount++);

    ai_list = realloc(ai_list, (count + scount + 1) * sizeof(*ai_list));
    if (ai_list == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }
    *indicators = ai_list;

    /* Steal decoder-allocated pointers.  */
    memcpy(ai_list + count, strdata, scount * sizeof(*strdata));
    count += scount;
    ai_list[count] = NULL;
    free(strdata);
    strdata = NULL;

cleanup:
    k5_free_data_ptr_list(strdata);
    return ret;
}
