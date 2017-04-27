/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kdc/kdc_policy.c - KDC-facing interface for policy plugin */
/*
 * Copyright (C) 2017 by Red Hat, Inc.
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

#include "k5-int.h"
#include "kdc_util.h"
#include <krb5/kdcpolicy_plugin.h>

typedef struct kdcpolicy_handle_st {
    struct krb5_kdcpolicy_vtable_st vt;
    krb5_kdcpolicy_moddata moddata;
} *kdcpolicy_handle;

static kdcpolicy_handle *kdcpolicy_handles;
static size_t n_policy_modules;

static void
free_kdcpolicy_handles(krb5_context context, kdcpolicy_handle *handles)
{
    int i;

    if (handles == NULL)
        return;
    for (i = 0; handles[i] != NULL; i++)
        free(handles[i]);
    free(handles);
}

krb5_error_code
krb5_kdcpolicy_profile_initvt(krb5_context context, int maj_ver, int min_ver,
                              krb5_plugin_vtable vtable);

krb5_error_code
load_kdcpolicy_plugins(struct server_handle *shandle, krb5_context context)
{
    krb5_error_code ret;
    krb5_plugin_initvt_fn *modules = NULL, *mod;
    kdcpolicy_handle *list = NULL, h;
    size_t count;

    kdcpolicy_handles = NULL;
    n_policy_modules = 0;

    ret = k5_plugin_register(context, PLUGIN_INTERFACE_KDCPOLICY, "profile",
                             krb5_kdcpolicy_profile_initvt);
    if (ret)
        goto cleanup;

    ret = k5_plugin_load_all(context, PLUGIN_INTERFACE_KDCPOLICY, &modules);
    if (ret)
        goto cleanup;

    /* Allocate handle list. */
    for (count = 0; modules[count]; count++);
    list = k5calloc(count + 1, sizeof(*list), &ret);
    if (list == NULL)
        goto cleanup;

    count = 0;
    for (mod = modules; *mod != NULL; mod++) {
        h = k5calloc(1, sizeof(*h), &ret);
        if (h == NULL)
            goto cleanup;

        ret = (*mod)(context, 1, 1, (krb5_plugin_vtable)&h->vt);
        if (ret) {
            //TRACE_KDCPOLICY_VTINIT_FAIL(context, ret);
            free(h);
            continue;
        }
        h->moddata = NULL;
        if (h->vt.init != NULL) {
            ret = h->vt.init(context, &h->moddata);
            if (ret) {
                //TRACE_KDCPOLICY_INIT_FAIL(context, h->vt.name, ret);
                free(h);
                continue;
            }
        }
        list[count++] = h;
        list[count] = NULL;
    }
    list[count] = NULL;

    ret = 0;
    kdcpolicy_handles = list;
    n_policy_modules = count;
    list = NULL;

cleanup:
    k5_plugin_free_modules(context, modules);
    free_kdcpolicy_handles(context, list);
    return ret;
}

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

static krb5_error_code
authind_strings(krb5_data **auth_indicators, char ***ais_out, size_t *n_ais)
{
    krb5_error_code ret = 0;
    size_t i, ai_count = 0;
    char **ais = NULL;

    *ais_out = NULL;
    *n_ais = 0;

    if (auth_indicators == NULL || auth_indicators[0] == NULL)
        goto cleanup;

    for (ai_count = 0; auth_indicators[ai_count] != NULL; ai_count++);

    ais = k5calloc(ai_count + 1, sizeof(*ais), &ret);
    for (i = 0; i < ai_count; i++) {
        ais[i] = k5memdup0(auth_indicators[i]->data,
                           auth_indicators[i]->length,
                           &ret);
        if (ais[i] == NULL)
            goto cleanup;
    }
    *ais_out = ais;
    ais = NULL;
    *n_ais = ai_count;

cleanup:
    free_indicators(ais);
    return ret;
}

/* Wrappers */
krb5_error_code
kdc_policy_get_ticket_endtime(kdc_realm_t *kdc_active_realm,
                              krb5_timestamp starttime, krb5_timestamp endtime,
                              krb5_timestamp till, krb5_db_entry *client,
                              krb5_db_entry *server,
                              krb5_data **auth_indicators,
                              krb5_timestamp *out_endtime)
{
    krb5_error_code ret = 0;
    kdcpolicy_handle h;
    size_t i, n_ais = 0;
    char **ais = NULL;
    krb5_timestamp end, prev;

    *out_endtime = 0;
    /* Turn auth indicators into string list */
    ret = authind_strings(auth_indicators, &ais, &n_ais);
    if (ret)
        goto cleanup;

    for (i = 0; i < n_policy_modules; i++) {
        h = kdcpolicy_handles[i];
        ret = h->vt.endtime(kdc_context, h->moddata, starttime, endtime, till,
                            kdc_active_realm->realm_maxlife, client, server,
                            ais, n_ais, &end);
        if (ret)
            goto cleanup;
        /* Use the shortest endtime given by all modules. */
        if (i == 0)
            prev = end;
        else
            prev = end = min(end, prev);
    }
    *out_endtime = end;

cleanup:
    free_indicators(ais);
    return ret;
}

krb5_error_code
kdc_policy_get_session_keytype(kdc_realm_t *kdc_active_realm,
                               krb5_db_entry *server, int nktypes,
                               krb5_enctype *ktype, krb5_data **auth_indicators,
                               krb5_enctype *enc_out)
{
    krb5_error_code ret;
    kdcpolicy_handle h;
    size_t i, n_ais = 0;
    krb5_enctype enc;
    char **ais = NULL;

    *enc_out = 0;

    /* Turn auth indicators into string list */
    ret = authind_strings(auth_indicators, &ais, &n_ais);
    if (ret)
        goto cleanup;

    /* run vt->etype() */
    for (i = 0; i < n_policy_modules; i++) {
        h = kdcpolicy_handles[i];
        ret = h->vt.etype(kdc_context, h->moddata, server, nktypes, ktype,
                          ais, n_ais, &enc,
                          kdc_active_realm->realm_assume_des_crc_sess);
        if (ret)
            goto cleanup;
    }
    *enc_out = enc;

cleanup:
    free_indicators(ais);
    return ret;
}

static krb5_error_code
profile_kdcpolicy_get_skey_etype(krb5_context context,
                                 krb5_kdcpolicy_moddata moddata,
                                 krb5_db_entry *server,
                                 int nktypes, krb5_enctype *ktypes,
                                 char **authinds, int n_ais,
                                 krb5_enctype *enc_out,
                                 uint32_t optional_flags)
{
    *enc_out = select_session_keytype(context, server, nktypes, ktypes,
                                      (krb5_boolean)optional_flags);
    return 0;
}

static krb5_error_code
profile_kdcpolicy_get_endtime(krb5_context context,
                              krb5_kdcpolicy_moddata moddata,
                              krb5_timestamp starttime, krb5_timestamp endtime,
                              krb5_timestamp till, krb5_deltat realm_maxlife,
                              krb5_db_entry *client, krb5_db_entry *server,
                              char **authinds, int n_ais,
                              krb5_timestamp *endtime_out)
{
    kdc_get_ticket_endtime(starttime, endtime, till, realm_maxlife,
                           client, server, endtime_out);
    return 0;
}

krb5_error_code
krb5_kdcpolicy_profile_initvt(krb5_context context, int maj_ver, int min_ver,
                              krb5_plugin_vtable vtable)
{
    krb5_kdcpolicy_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
    vt = (krb5_kdcpolicy_vtable)vtable;
    vt->name = "profile";
    vt->etype = profile_kdcpolicy_get_skey_etype;
    vt->endtime = profile_kdcpolicy_get_endtime;
    return 0;
}
