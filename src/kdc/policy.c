/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kdc/policy.c - Policy decision routines for KDC */
/*
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
#include "kdc_util.h"
#include "extern.h"
#include "policy.h"
#include <krb5/kdcpolicy_plugin.h>

typedef struct kdcpolicy_handle_st {
    struct krb5_kdcpolicy_vtable_st vt;
    krb5_kdcpolicy_moddata moddata;
} *kdcpolicy_handle;

static kdcpolicy_handle kdcpolh;

static void
free_indicators(char **ais)
{
    int i;

    if (ais == NULL)
        return;
    for (i = 0; ais[i] != NULL; i++)
        free(ais[i]);
    free(ais);
}

/* Convert krb5_data indicators into a NULL-terminated list of indicator
 * strings. */
static krb5_error_code
authind_strings(krb5_data **auth_indicators, char ***ais_out)
{
    krb5_error_code ret = 0;
    size_t i, ai_count = 0;
    char **ais = NULL;

    *ais_out = NULL;

    if (auth_indicators == NULL || auth_indicators[0] == NULL)
        goto cleanup;

    for (ai_count = 0; auth_indicators[ai_count] != NULL; ai_count++);

    ais = k5calloc(ai_count + 1, sizeof(*ais), &ret);
    if (ais == NULL)
        goto cleanup;

    for (i = 0; i < ai_count; i++) {
        ais[i] = k5memdup0(auth_indicators[i]->data,
                           auth_indicators[i]->length,
                           &ret);
        if (ais[i] == NULL)
            goto cleanup;
    }
    *ais_out = ais;
    ais = NULL;

cleanup:
    free_indicators(ais);
    return ret;
}

/*
 * Check the AS request against the local AS policy, returning 0 and a
 * NULL *status string on success or non-0 and a *status string literal on
 * failure.  Output the module-produced ticket endtime and session-key
 * enctype.  Accepts an authentication indicator to pass to the module for
 * policy decisions.
 */
krb5_error_code
against_local_policy_as(krb5_context context,
                        register krb5_kdc_req *request,
                        krb5_db_entry *client,
                        krb5_db_entry *server,
                        krb5_data **auth_indicators,
                        krb5_timestamp kdc_time,
                        const char **status,
                        krb5_timestamp *tkt_end_out,
                        krb5_enctype *skey_enc_out)
{
    krb5_error_code ret = 0;
    const char *st = NULL;
    krb5_timestamp end;
    krb5_enctype enc;
    char **ais = NULL;

    *tkt_end_out = 0;
    *skey_enc_out = ENCTYPE_NULL;

    if (kdcpolh == NULL)
        goto cleanup;

    if (kdcpolh->vt.local_as == NULL)
        goto cleanup;

    ret = authind_strings(auth_indicators, &ais);
    if (ret)
        goto cleanup;

    ret = kdcpolh->vt.local_as(context,
                               request,
                               client,
                               server,
                               (const char **)ais,
                               &st,
                               &end,
                               &enc);

    if (ret == 0 && st == NULL) {
        *tkt_end_out = end;
        *skey_enc_out = enc;
    }
    *status = st;

cleanup:
    free_indicators(ais);
    return ret;
}


/*
 * Check the TGS request against the local TGS policy, returning 0 and a
 * NULL *status string on success or non-0 and a *status string literal on
 * failure.  Output the module-produced ticket endtime and session-key
 * enctype.  Accepts an authentication indicator to pass to the module for
 * policy decisions.
 */
krb5_error_code
against_local_policy_tgs(krb5_context context,
                         register krb5_kdc_req *request,
                         krb5_db_entry *server,
                         krb5_ticket *ticket,
                         krb5_data **auth_indicators,
                         krb5_timestamp kdc_time,
                         const char **status,
                         krb5_timestamp *tkt_end_out,
                         krb5_enctype *skey_enc_out)
{
    krb5_error_code ret = 0;
    const char *st = NULL;
    krb5_deltat del;
    krb5_timestamp endtime = 0;
    krb5_enctype enc;
    char **ais = NULL;
    char *end_string = NULL;

    *tkt_end_out = 0;
    *skey_enc_out = ENCTYPE_NULL;
    *status = NULL;

    if (kdcpolh == NULL)
        goto end;

    if (kdcpolh->vt.local_tgs == NULL)
        goto end;

    ret = authind_strings(auth_indicators, &ais);
    if (ret)
        goto end;

    ret = kdcpolh->vt.local_tgs(context, request,
                                server,
                                ticket,
                                (const char **)ais,
                                &st,
                                &end_string,
                                &enc);

    if (ret)
        goto end;

    if (end_string != NULL) {
        ret = krb5_string_to_deltat(end_string, &del);
        if (ret) {
            st = "LOCAL_POLICY_ERR";
            goto end;
        }
        endtime = kdc_time + del;
    }

    *tkt_end_out = endtime;
    *skey_enc_out = enc;

end:
    *status = st;
    free_indicators(ais);
    return ret;
}

/* Load a KDC Policy plugin module. */
krb5_error_code
load_kdcpolicy_plugin(struct server_handle *shandle, krb5_context context)
{
    krb5_error_code ret;
    krb5_plugin_initvt_fn *modules = NULL;
    kdcpolicy_handle h = NULL;

    kdcpolh = NULL;

    ret = k5_plugin_load_all(context, PLUGIN_INTERFACE_KDCPOLICY, &modules);
    if (ret)
        goto cleanup;

    if (modules == NULL || *modules == NULL)
        goto cleanup;

    /* Allocate handle. */
    h = k5calloc(1, sizeof(*h), &ret);
    if (h == NULL)
        goto cleanup;

    /* Load the first module. */
    ret = (*modules)(context, 1, 1, (krb5_plugin_vtable)&h->vt);
    if (ret) {
        TRACE_KDCPOLICY_VTINIT_FAIL(context, ret);
        goto cleanup;
    }

    h->moddata = NULL;
    if (h->vt.init != NULL)
        ret = h->vt.init(context, &h->moddata);

    if (ret) {
        TRACE_KDCPOLICY_INIT_FAIL(context, h->vt.name, ret);
        goto cleanup;
    }

    kdcpolh = h;
    h = NULL;

cleanup:
    k5_plugin_free_modules(context, modules);
    free(h);
    return ret;
}
