/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* include/krb5/certauth_plugin.h
 * Certificate authorization plugin interface */
/*
 * Copyright (C) 2016, 2017 by Red Hat Software, Inc.
 * All rights reserved.
 *
 * Copyright (C) 2013 by the Massachusetts Institute of Technology.
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

#include <krb5/krb5.h>
#include <krb5/plugin.h>

/* Certificate authorization plugin interface. */

typedef struct krb5_certauth_moddata_st *krb5_certauth_moddata;

typedef void
(*krb5_certauth_init_fn)(krb5_certauth_moddata *moddata_out);

typedef void
(*krb5_certauth_fini_fn)(krb5_certauth_moddata moddata);

/* 
 * XXX
 * Check if cert (ASN.1 encoded) is authorized to authenticate princ or the
 * principal from db_entry if the module is KDB-aware.
 * The *authinds output contains any authentication indicators inserted by the module.
 * The status output contains the resulting authorization status.
 * YES - Authorized
 * NO - Not authorized
 * PASS - Skip (with possible authinds output)
 * 
 * If the module not KDB-aware, then db_entry is ignored.
 */
typedef krb5_error_code
(*krb5_certauth_authorize_fn)(krb5_context context,
                              krb5_certauth_moddata moddata,
                              krb5_data cert, void *db_entry,
                              krb5_principal princ, char **authinds_out,
                              int *status);

typedef struct krb5_certauth_vtable_st {
    char *name;
    krb5_certauth_init_fn init;
    krb5_certauth_fini_fn fini;
    krb5_certauth_authorize_fn authorize;
} *krb5_certauth_vtable;

