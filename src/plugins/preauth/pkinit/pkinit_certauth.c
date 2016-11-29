
#include <k5-int.h>
#include <include/krb5/certauth_plugin.h>

static void
server_certauth_ini(krb5_context context)
{

}

static void
server_certauth_fini(krb5_context context)
{

}

static krb5_error_code
server_authorize_cert(krb5_context context, krb5_octet *cert, void *db_entry,
                      krb5_principal princ, krb5_authdata **authinds,
                      int *status)
{
    return 0;
}

krb5_error_code
certauth_initvt(krb5_context context, int maj_ver, int min_ver,
                                  krb5_plugin_vtable vtable)
{
    krb5_certauth_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
    vt = (krb5_certauth_vtable)vtable;
    vt->name = "certauth";
    vt->init = server_certauth_init;
    vt->fini = pkinit_server_plugin_fini;
    vt->authorize = server_authorize_cert;
    return 0;
}
