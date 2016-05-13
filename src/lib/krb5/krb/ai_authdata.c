/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* src/lib/krb5/krb/ai_authdata.c - Auth indicator AD backend */
/*
 * Copyright (C) 2016 by the Massachusetts Institute of Technology.
 * Copyright (C) 2016 by Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Authdata backend for authentication indicators.
 */

#include "k5-int.h"
#include "authdata.h"
#include "auth_con.h"
#include "int-proto.h"

struct authind_context {
    krb5_authdata **export_ind; /* Encoded copy for export. */
    krb5_data *indicators;      /* Decoded. */
    krb5_boolean authenticated;
    int count;
};

static krb5_error_code
authind_init(krb5_context kcontext, void **plugin_context)
{
    *plugin_context = NULL;
    return 0;
}

static void
authind_flags(krb5_context kcontext, void *plugin_context,
              krb5_authdatatype ad_type, krb5_flags *flags)
{
    *flags = AD_USAGE_AP_REQ;
}

static krb5_error_code
authind_request_init(krb5_context kcontext, krb5_authdata_context context,
                     void *plugin_context, void **request_context)
{
    krb5_error_code ret = 0;
    struct authind_context *aictx;

    aictx = k5alloc(sizeof(*aictx), &ret);
    if (aictx == NULL)
        return ret;

    aictx->export_ind = NULL;
    aictx->indicators = NULL;
    aictx->count = 0;
    aictx->authenticated = FALSE;

    *request_context = aictx;

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

static krb5_error_code
update_authind_data(krb5_context kcontext, struct authind_context *aictx,
                    krb5_authdata **export_ind, krb5_data **ind)
{
    krb5_error_code ret;
    krb5_data *tmp;
    int count, i;

    /* Copy values to the krb5_data array that authind_get_attribute() uses for
     * output. */
    for (count = 0; ind != NULL && ind[count] != NULL; count++);
    if (count == 0)
        return ENOENT;

    tmp = k5calloc(count + 1, sizeof(*tmp), &ret);
    if (tmp == NULL)
        return errno;

    for (i = 0; i < count; i++) {
        ret = krb5int_copy_data_contents_add0(kcontext, ind[i], &tmp[i]);
        if (ret != 0)
            goto cleanup;
    }

    aictx->count = count;
    aictx->indicators = tmp;
    /* Indicators are delivered in a CAMMAC verified outside of this module,
     * so these are authenticated values. */
    aictx->authenticated = TRUE;
    tmp = NULL;

    /* Make a copy of the original authdata for authind_export_authdata(). */
    ret = krb5_copy_authdata(kcontext, export_ind, &aictx->export_ind);

cleanup:
    krb5int_free_data_list(kcontext, tmp);
    return ret;
}

static krb5_error_code
authind_import_authdata(krb5_context kcontext, krb5_authdata_context context,
                        void *plugin_context, void *request_context,
                        krb5_authdata **authdata, krb5_boolean kdc_issued,
                        krb5_const_principal kdc_issuer)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret = 0;
    krb5_data **indps = NULL;
    int i;

    for (i = 0; authdata != NULL && authdata[i] != NULL; i++) {
        ret = k5_authind_decode(authdata[i], &indps);
        if (ret != 0)
            goto cleanup;
    }

    ret = update_authind_data(kcontext, aictx, authdata, indps);

cleanup:
    k5_free_data_ptr_list(indps);
    return ret;
}

static krb5_error_code
authind_export_authdata(krb5_context kcontext, krb5_authdata_context context,
                        void *plugin_context, void *request_context,
                        krb5_flags usage, krb5_authdata ***out_authdata)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret;
    krb5_authdata **cad;

    *out_authdata = NULL;
    if (aictx->export_ind == NULL)
        return 0;

    ret = krb5_copy_authdata(kcontext, aictx->export_ind, &cad);
    if (ret == 0)
        *out_authdata = cad;

    return ret;
}

static void
authind_request_fini(krb5_context kcontext, krb5_authdata_context context,
                     void *plugin_context, void *request_context)
{
    struct authind_context *aictx = (struct authind_context *)request_context;

    if (aictx == NULL)
        return;

    krb5_free_authdata(kcontext, aictx->export_ind);
    krb5int_free_data_list(kcontext, aictx->indicators);
    free(aictx);
}

/* This is a non-URI "local attribute" that is implementation defined. */
static krb5_data authentication_indicators_attr = {
    KV5M_DATA,
    sizeof("auth-indicators") - 1,
    "auth-indicators"
};

static krb5_error_code
authind_get_attribute_types(krb5_context kcontext,
                            krb5_authdata_context context, void *plugin_context,
                            void *request_context, krb5_data **out_attrs)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret;
    krb5_data *attrs;

    *out_attrs = NULL;

    if (aictx->indicators == NULL)
        return ENOENT;

    attrs = k5calloc(2, sizeof(*attrs), &ret);
    if (attrs == NULL)
        return ENOMEM;

    ret = krb5int_copy_data_contents(kcontext, &authentication_indicators_attr,
                                     &attrs[0]);
    if (ret)
        goto cleanup;

    attrs[1].data = NULL;
    attrs[1].length = 0;

    *out_attrs = attrs;
    attrs = NULL;

cleanup:
    krb5int_free_data_list(kcontext, attrs);
    return ret;
}

static krb5_error_code
authind_get_attribute(krb5_context kcontext, krb5_authdata_context context,
                      void *plugin_context, void *request_context,
                      const krb5_data *attribute, krb5_boolean *authenticated,
                      krb5_boolean *complete, krb5_data *value,
                      krb5_data *display_value, int *more)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret;
    krb5_data *value_out;
    int i;

    if (!data_eq(*attribute, authentication_indicators_attr))
        return ENOENT;

    i = -(*more) - 1;
    if (i < 0)
        return EINVAL;
    else if (i >= aictx->count)
        return ENOENT;

    ret = krb5_copy_data(kcontext, &aictx->indicators[i], &value_out);
    if (ret)
        return ret;

    i++;

    if (i == aictx->count)
        *more = 0;
    else
        *more = -(i + 1);

    *value = *value_out;
    *authenticated = aictx->authenticated;
    *complete = TRUE;

    free(value_out);
    return ret;
}

static krb5_error_code
authind_set_attribute(krb5_context kcontext, krb5_authdata_context context,
                      void *plugin_context, void *request_context,
                      krb5_boolean complete, const krb5_data *attribute,
                      const krb5_data *value)
{
    /* Indicators are imported from ticket authdata, not set by this module. */
    if (!data_eq(*attribute, authentication_indicators_attr))
        return ENOENT;

    return EPERM;
}

static krb5_error_code
authind_export_internal(krb5_context kcontext, krb5_authdata_context context,
                        void *plugin_context, void *request_context,
                        krb5_boolean restrict_authenticated, void **ptr)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret;
    int i;
    krb5_data *inds;

    *ptr = NULL;

    if (aictx->count == 0)
        return ENOENT;

    if (restrict_authenticated && aictx->authenticated != TRUE)
        return ENOENT;

    inds = k5calloc(aictx->count + 1, sizeof(*inds), &ret);
    if (inds == NULL)
        return ret;

    for (i = 0; i < aictx->count; i++) {
        ret = krb5int_copy_data_contents(kcontext, &aictx->indicators[i],
                                         &inds[i]);
        if (ret)
            goto cleanup;
    }

    inds[i].data = NULL;
    inds[i].length = 0;

    *ptr = inds;
    inds = NULL;

cleanup:
    krb5int_free_data_list(kcontext, inds);
    return ret;
}

static krb5_error_code
authind_size(krb5_context kcontext, krb5_authdata_context context,
             void *plugin_context, void *request_context, size_t *sizep)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret = 0;
    int i;

    *sizep += sizeof(krb5_int32); /* version */
    *sizep += sizeof(krb5_int32); /* authind count */

    for (i = 0; i < aictx->count; i++) {
        *sizep += sizeof(krb5_int32) + /* length */
                  (size_t)aictx->indicators[i].length;
    }
    *sizep += sizeof(krb5_int32); /* authenticated flag */

    return ret;
}

static krb5_error_code
authind_externalize(krb5_context kcontext, krb5_authdata_context context,
                    void *plugin_context, void *request_context,
                    krb5_octet **buffer, size_t *lenremain)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret = 0;
    size_t required = 0;
    krb5_octet *bp;
    size_t remain;
    int i = 0;

    bp = *buffer;
    remain = *lenremain;

    authind_size(kcontext, context, plugin_context,
                   request_context, &required);

    if (required > remain)
        return ENOMEM;

    krb5_ser_pack_int32(1, &bp, &remain); /* version */
    krb5_ser_pack_int32(aictx->count, &bp, &remain); /* authind count */

    for (i = 0; i < aictx->count; i++) {
        krb5_ser_pack_int32(aictx->indicators[i].length, &bp, &remain);
        ret = krb5_ser_pack_bytes((krb5_octet *)aictx->indicators[i].data,
                                  (size_t)aictx->indicators[i].length,
                                  &bp, &remain);
        if (ret)
            return ret;
    }

    /* authenticated */
    krb5_ser_pack_int32(aictx->authenticated, &bp, &remain);

    *buffer = bp;
    *lenremain = remain;

    return ret;
}

/* Unpack and verify version number and count. */
static krb5_error_code
internal_unpack_vc(krb5_octet **bp, size_t *remain, krb5_int32 *cnt)
{
    krb5_error_code ret;
    krb5_int32 v, c;

    *cnt = 0;

    ret = krb5_ser_unpack_int32(&v, bp, remain);
    if (ret != 0)
        return ret;

    if (v != 1)
        return EINVAL;

    ret = krb5_ser_unpack_int32(&c, bp, remain);
    if (ret != 0)
        return ret;

    if (c > 65535)
        return ERANGE; /* What is a proper limit here? */

    *cnt = c;

    return ret;
}

/* Unpack indicator data. */
static krb5_error_code
internal_unpack_ind_data(krb5_context kcontext, krb5_octet **bp, size_t *remain,
                         krb5_int32 count, krb5_data **indicators)
{
    krb5_error_code ret;
    krb5_data *inds = NULL;
    krb5_int32 ibuf;
    int i;

    *indicators = NULL;

    inds = k5calloc(count + 1, sizeof(*inds), &ret);
    if (ret != 0)
        return errno;

    for (i = 0; i < count; i++) {
        /* Get the length */
        (void)krb5_ser_unpack_int32(&ibuf, bp, remain);

        inds[i].data = k5alloc(ibuf, &ret);
        if (ret != 0)
            goto cleanup;

        ret = krb5_ser_unpack_bytes((krb5_octet *)inds[i].data, (size_t)ibuf,
                                    bp, remain);
        if (ret != 0)
            goto cleanup;

        inds[i].length = ibuf;
        inds[i].magic = KV5M_DATA;
    }

    inds[i] = empty_data();
    *indicators = inds;
    inds = NULL;

cleanup:
    krb5int_free_data_list(kcontext, inds);
    return ret;
}

static krb5_error_code
authind_internalize(krb5_context kcontext, krb5_authdata_context context,
                    void *plugin_context, void *request_context,
                    krb5_octet **buffer, size_t *lenremain)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret;
    krb5_int32 abuf, count;
    krb5_octet *bp;
    size_t remain;
    krb5_data *inds = NULL;

    bp = *buffer;
    remain = *lenremain;

    ret = internal_unpack_vc(&bp, &remain, &count);
    if (ret != 0)
        goto cleanup;

    ret = internal_unpack_ind_data(kcontext, &bp, &remain, count, &inds);
    if (ret != 0)
        goto cleanup;

    /* Authenticated flag. */
    ret = krb5_ser_unpack_int32(&abuf, &bp, &remain);
    if (ret != 0)
        goto cleanup;

    krb5int_free_data_list(kcontext, aictx->indicators);

    aictx->count = (int)count;
    aictx->indicators = inds;
    aictx->authenticated = (abuf != 0);

    inds = NULL;

    *buffer = bp;
    *lenremain = remain;

cleanup:
    krb5int_free_data_list(kcontext, inds);
    return ret;
}

static krb5_error_code
authind_copy(krb5_context kcontext, krb5_authdata_context context,
             void *plugin_context, void *request_context,
             void *dst_plugin_context, void *dst_req_context)
{
    struct authind_context *srcctx = (struct authind_context *)request_context;
    struct authind_context *dstctx = (struct authind_context *)dst_req_context;
    krb5_error_code ret;

    ret = authind_export_internal(kcontext, context, plugin_context,
                                  request_context, FALSE,
                                  (void **)&dstctx->indicators);
    if (ret && ret != ENOENT)
        return ret;

    dstctx->count = srcctx->count;
    dstctx->authenticated = srcctx->authenticated;

    return 0;
}

static krb5_authdatatype authind_ad_types[] = {
    KRB5_AUTHDATA_AUTH_INDICATOR, 0
};

krb5plugin_authdata_client_ftable_v0 k5_authind_ad_client_ftable = {
    "authentication-indicators",
    authind_ad_types,
    authind_init,
    NULL, /* fini */
    authind_flags,
    authind_request_init,
    authind_request_fini,
    authind_get_attribute_types,
    authind_get_attribute,
    authind_set_attribute,
    NULL, /* delete_attribute_proc */
    authind_export_authdata,
    authind_import_authdata,
    authind_export_internal,
    NULL, /* free_internal */
    NULL, /* verify */
    authind_size,
    authind_externalize,
    authind_internalize,
    authind_copy
};
