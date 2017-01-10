/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* include/krb5/certauth_plugin.h
 *
 * Copyright (C) 2016, 2017 by Red Hat, Inc.
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

/* Abstract module data type. */
typedef struct krb5_certauth_moddata_st *krb5_certauth_moddata;

/*
 * Initialize a per-request moddata.  This is optional for custom
 * modules.
 * - opts is used by the builtin kdc module and can be ignored by custom
 *   modules.
 */
typedef krb5_error_code
(*krb5_certauth_req_init_fn)(krb5_context context, void *opts,
                             krb5_certauth_moddata *moddata_out);

/*
 * Clean up the per-request moddata.
 */
typedef void
(*krb5_certauth_req_fini_fn)(krb5_context context,
                             krb5_certauth_moddata *moddata);

/*
 * Is princ allowed to PKINIT using the DER encoded cert?
 * While there is nothing to prevent a module from doing a full certificate
 * verification, that has already been performed by kdcpreauth so a module can
 * assume the certificate is valid, and perform a policy check against certificate
 * extensions such as SAN/EKU or other attributes.
 *
 * status: TRUE for OK/PASS.
 *         FALSE for NO (explicitly failed authorization)
 *
 * TODO parts not plugged in:
 *  - optional db_entry: Intended for modules that need KDB checks for
 *    valid principal names or aliases contained in certificate extensions.
 *    (Note: The kdcpreauth builtin module uses the req_init_fn optional cb and
 *    cb_data (kdcpreauth callbacks and preauth rock) arguments for the KDB
 *    checks using match_client.)
 *  - optional *authinds_out: Intended to fill in auth indicators from the
 *    certificate. 
 */
typedef krb5_error_code
(*krb5_certauth_authorize_fn)(krb5_context context,
                              krb5_certauth_moddata moddata, krb5_data cert,
                              krb5_principal princ, void *db_entry,
                              char **authinds_out, krb5_boolean *status);

typedef struct krb5_certauth_vtable_st {
    char *name;
    krb5_certauth_req_init_fn req_init;
    krb5_certauth_req_fini_fn req_fini;
    krb5_certauth_authorize_fn authorize;
} *krb5_certauth_vtable;

