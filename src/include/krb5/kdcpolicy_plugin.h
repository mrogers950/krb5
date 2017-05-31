/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* krb5/kdclocalpolicy_plugin.h - KDC local policy plugin interface. */
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

/*
 *
 */

#ifndef KRB5_KDCPOLICY_PLUGIN_H
#define KRB5_KDCPOLICY_PLUGIN_H
#include <krb5/krb5.h>

typedef struct krb5_kdcpolicy_moddata_st *krb5_kdcpolicy_moddata;
typedef struct _krb5_db_entry_new krb5_db_entry;

typedef krb5_error_code
(*krb5_kdcpolicy_init_fn)(krb5_context context,
                          krb5_kdcpolicy_moddata *moddata);

typedef krb5_error_code
(*krb5_kdcpolicy_fini_fn)(krb5_kdcpolicy_moddata moddata);

typedef krb5_error_code
(*krb5_kdcpolicy_local_as_fn)(krb5_context context,
                                krb5_kdc_req *request,
                                krb5_db_entry *client,
                                krb5_db_entry *server,
                                const char **auth_indicators,
                                const char **status,
                                /* Default tkt end function */
                                krb5_timestamp *tkt_end_out,
                                /* Default skey enc function */
                                krb5_enctype *skey_enc_out);

typedef krb5_error_code
(*krb5_kdcpolicy_local_tgs_fn)(krb5_context context,
                                krb5_kdc_req *request,
                                krb5_db_entry *server,
                                krb5_ticket *ticket,
                                const char **auth_indicators,
                                const char **status,
                                /* Default tkt end function */
                                char **tkt_end_out,
                                /* Default skey enc function */
                                krb5_enctype *skey_enc_out);

typedef struct krb5_kdcpolicy_vtable_st {
    char *name;
    krb5_kdcpolicy_init_fn init;
    krb5_kdcpolicy_fini_fn fini;
    krb5_kdcpolicy_local_as_fn local_as;
    krb5_kdcpolicy_local_tgs_fn local_tgs;
} *krb5_kdcpolicy_vtable;

#endif /* KRB5_KDCPOLICY_PLUGIN_H */
