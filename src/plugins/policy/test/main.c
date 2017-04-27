/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* test/main.c - KDC TGS policy plugin test module. */
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
#include <krb5/kdcpolicy_plugin.h>

static krb5_error_code
test_get_etype(krb5_context context, krb5_kdcpolicy_moddata moddata,
               krb5_db_entry *server, int nktypes, krb5_enctype *ktypes,
               char **authinds, int n_ais, krb5_enctype *enc_out,
               uint32_t optional_flags)
{
    int i;
    krb5_enctype enc = ENCTYPE_DES3_CBC_SHA1;

    if (authinds != NULL && n_ais > 0) {
        for (i = 0; i < n_ais; i++) {
            if (strcmp(authinds[i], "fast") == 0) {
                enc = ENCTYPE_AES128_CTS_HMAC_SHA1_96;
                break;
            } else if (strcmp(authinds[i], "pkinit") == 0) {
                enc = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
                break;
            }
        }
    }
    *enc_out = enc;
    return 0;
}

#define min(a, b) ((a) < (b) ? (a) : (b))

static krb5_error_code
test_get_endtime(krb5_context context, krb5_kdcpolicy_moddata moddata,
                 krb5_timestamp starttime, krb5_timestamp endtime,
                 krb5_timestamp till, krb5_deltat realm_maxlife,
                 krb5_db_entry *client, krb5_db_entry *server, char **authinds,
                 int n_ais, krb5_timestamp *endtime_out)
{
    int i;
    char *ts = "24:00";
    krb5_timestamp until, life;
    krb5_deltat del;

    if (authinds != NULL && n_ais > 0) {
        for (i = 0; i < n_ais; i++) {
            if (strcmp(authinds[i], "fast") == 0) {
                ts = "1:00";
                break;
            } else if (strcmp(authinds[i], "pkinit") == 0) {
                ts = "2:00";
                break;
            }
        }
    }

    if (till == 0)
        till = KRB5_INT32_MAX;

    until = min(till, endtime);
    life = until - starttime;

    assert(krb5_string_to_deltat(ts, &del) == 0);

    *endtime_out = starttime + min(life, del);

    return 0;
}

krb5_error_code
kdcpolicy_test_initvt(krb5_context context, int maj_ver, int min_ver,
                           krb5_plugin_vtable vtable)
{
    krb5_kdcpolicy_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
    vt = (krb5_kdcpolicy_vtable)vtable;
    vt->name = "test";
    vt->etype = test_get_etype;
    vt->endtime = test_get_endtime;
    return 0;
}
