#!/usr/bin/env python3
"""Write only the owner trust module for the plugin's three CDHashes (trust.json of build-adreno-metal-plugin.py).

  owner-trust-module.py TRUST_JSON OUTPUT

The bytes are exactly the first module make-owner-trust-bundle.py builds (version 2, uuid5 identifier, CDHashes ascending,
hash type 2), without the two original Apple modules: those never enter the CI job. componi-gpu-addon.py on the PC prepends
this module to the original bundle and checks the result like the boot loader does."""
import json
from pathlib import Path
import struct
import sys
import uuid


def owner_module(trust):
    hashes = sorted([bytes.fromhex(trust['cdhash']), bytes.fromhex(trust['daemon_cdhash']), bytes.fromhex(trust['turnip_cdhash'])])
    if len(set(hashes)) != len(hashes) or any(len(h) != 20 for h in hashes):
        raise SystemExit('Duplicate or malformed CDHash')
    identifier = uuid.uuid5(uuid.NAMESPACE_URL, 'org.blu-sharky.adreno-metal:' + ''.join(h.hex() for h in hashes))
    return struct.pack('<I16sI', 2, identifier.bytes, len(hashes)) + b''.join(h + bytes([2, 0, 0, 0]) for h in hashes)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    module = owner_module(json.loads(Path(sys.argv[1]).read_text()))
    Path(sys.argv[2]).write_bytes(module)
    print(f'owner trust module: {len(module)} bytes, {(len(module) - 24) // 24} CDHashes')
