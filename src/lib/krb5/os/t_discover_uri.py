#!/usr/bin/python
from k5test import *

entries = ['URI _krb5kdc.TEST krb5srv:m:kkdcp:https://kdc/path 10 1\n',
           'URI _krb5kdc.TEST krb5srv::kkdcp:https://kdc 20 1\n']
f = open(sys.argv[2], 'w')
for line in entries:
    f.write(line)
f.close()

conf = { 'libdefaults': { 'dns_lookup_kdc' : 'true' }}
realm = K5Realm(create_kdb=False, krb5_conf=conf)

# Path to libresolv_wrapper.so
realm.env['LD_PRELOAD'] = sys.argv[1]
realm.env['RESOLV_WRAPPER_HOSTS'] = sys.argv[2]

out = realm.run(['./t_locate_kdc', 'TEST'], env=realm.env)
print out

fail("stopping")
