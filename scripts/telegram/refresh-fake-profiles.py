#!/usr/bin/env python3
"""Re-issue the expired fake provisioning profiles of Telegram-iOS (build-system/fake-codesigning/profiles).

The upstream fake profiles are CMS blobs signed by the self-signed 'OU=SELFSIGNED' certificate in
build-system/fake-codesigning/certs/SelfSigned.p12 (empty password). rules_apple's plisttool refuses a profile whose
ExpirationDate is in the past (the upstream ones expired 2026-10-30), so this rewrites only ExpirationDate/TimeToLive and
signs the plist again with the same self-signed key. Nothing else changes (entitlements, team, DeveloperCertificates).

  refresh-fake-profiles.py <fake-codesigning dir>
"""
import datetime
import os
import plistlib
import subprocess
import sys
import tempfile

root = sys.argv[1]
profiles = os.path.join(root, 'profiles')
p12 = os.path.join(root, 'certs', 'SelfSigned.p12')
work = tempfile.mkdtemp()
key = os.path.join(work, 'key.pem')


def openssl(*args, check=True):
    return subprocess.run(['openssl', *args], capture_output=True, check=check)


# OpenSSL 3 needs -legacy for the RC2-40 p12; LibreSSL (/usr/bin/openssl on macOS) has no -legacy flag.
if openssl('pkcs12', '-legacy', '-in', p12, '-passin', 'pass:', '-nodes', '-out', key, check=False).returncode != 0 \
        or os.path.getsize(key) == 0:
    openssl('pkcs12', '-in', p12, '-passin', 'pass:', '-nodes', '-out', key)
now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None, microsecond=0)
expire = now + datetime.timedelta(days=365)
for name in sorted(os.listdir(profiles)):
    if not name.endswith('.mobileprovision'):
        continue
    path = os.path.join(profiles, name)
    content = openssl('smime', '-verify', '-noverify', '-inform', 'DER', '-in', path).stdout
    plist = plistlib.loads(content)
    old = plist.get('ExpirationDate')
    if old and old > now + datetime.timedelta(days=2):
        print(f'{name}: ExpirationDate {old} ok')
        continue
    plist['ExpirationDate'] = expire
    plist['TimeToLive'] = 365
    src = os.path.join(work, name + '.plist')
    with open(src, 'wb') as fh:
        plistlib.dump(plist, fh)
    openssl('smime', '-sign', '-nodetach', '-binary', '-outform', 'DER', '-md', 'sha256', '-in', src, '-signer', key, '-inkey', key,
            '-out', path)
    check = plistlib.loads(openssl('smime', '-verify', '-noverify', '-inform', 'DER', '-in', path).stdout)
    assert check['ExpirationDate'] == expire and check['Entitlements'] == plist['Entitlements'], name
    print(f'{name}: ExpirationDate {old} -> {expire}')
os.remove(key)
