#!/usr/bin/python
from k5test import *

# Skip this test if pkinit wasn't built.
if not os.path.exists(os.path.join(plugins, 'preauth', 'pkinit.so')):
    skip_rest('PKINIT tests', 'PKINIT module not built')

modpath = os.path.join(buildtop, 'plugins', 'policy', 'test',
                       'policy_test.so')
certs = os.path.join(srctop, 'tests', 'dejagnu', 'pkinit-certs')
ca_pem = os.path.join(certs, 'ca.pem')
kdc_pem = os.path.join(certs, 'kdc.pem')
user_pem = os.path.join(certs, 'user.pem')
privkey_pem = os.path.join(certs, 'privkey.pem')
file_identity = 'FILE:%s,%s' % (user_pem, privkey_pem)
krb5conf = {'realms': {'$realm': {
    'pkinit_anchors': 'FILE:%s' % ca_pem}},
            'plugins': {'kdcpolicy': {'module': 'test:' + modpath}}}
kdcconf = {'realms': {'$realm': {
            'default_principal_flags': '+preauth',
            'pkinit_eku_checking': 'none',
            'pkinit_identity': 'FILE:%s,%s' % (kdc_pem, privkey_pem),
            'pkinit_indicator': ['pkinit'],
            'encrypted_challenge_indicator': ['fast']}}}

realm = K5Realm(krb5_conf=krb5conf, kdc_conf=kdcconf)
realm.run([kadminl, 'addprinc', '+requires_preauth', '-pw', password('test'),
           'fastuser'])

# Set principal defaults.
#realm.run([kadminl, 'modprinc', '-maxlife', '20 minutes',
#           realm.host_princ])
#realm.run([kadminl, 'modprinc', '-maxlife', '20 minutes', pr1])

# Obtain PKINIT indicator.
realm.kinit(realm.user_princ,
            flags=['-X', 'X509_user_identity=%s' % file_identity])
realm.run([kvno, realm.host_princ])
realm.run(['./adata', realm.host_princ], expected_msg='+97: [pkinit]')
realm.run([klist, realm.ccache, '-e'])
# Verify service ticket time/skey enc here; 

# Obtain FAST indicator.
realm.kinit('fastuser@%s' % realm.realm, password('test'))
realm.kinit('fastuser@%s' % realm.realm, password('test'), flags=['-T', realm.ccache])
realm.run([kvno, realm.host_princ])
realm.run(['./adata', realm.host_princ], expected_msg='+97: [fast]')
realm.run([klist, realm.ccache, '-e'])
# Verify service ticket time/skey enc here;

fail('XXX - stopping')
