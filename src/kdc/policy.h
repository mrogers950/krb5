/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kdc/policy.h - Declarations for policy.c */
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

#ifndef __KRB5_KDC_POLICY__
#define __KRB5_KDC_POLICY__
#include "k5-int.h"
#include "kdc_util.h"
#include "extern.h"

//extern int against_postdate_policy (krb5_timestamp);

//extern int against_flag_policy_as (const krb5_kdc_req *);

//extern int against_flag_policy_tgs (const krb5_kdc_req *,
//                                    const krb5_ticket *);

krb5_error_code
load_kdcpolicy_plugin(struct server_handle *shandle,
                      krb5_context context);

krb5_error_code
against_local_policy_as(krb5_context context,
                        register krb5_kdc_req *request,
                        krb5_db_entry *client,
                        krb5_db_entry *server,
                        krb5_data **auth_indicators,
                        krb5_timestamp kdc_time,
                        const char **status,
                        krb5_timestamp *tkt_end_out,
                        krb5_enctype *skey_enc_out);

krb5_error_code
against_local_policy_tgs(krb5_context context,
                         register krb5_kdc_req *request,
                         krb5_db_entry *server,
                         krb5_ticket *ticket,
                         krb5_data **auth_indicators,
                         krb5_timestamp kdc_time,
                         const char **status,
                         krb5_timestamp *tkt_end_out,
                         krb5_enctype *skey_enc_out);

#endif /* __KRB5_KDC_POLICY__ */
