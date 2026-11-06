#!/usr/bin/env python3
"""Scan every arm64 Mach-O slice under a directory (or single files) for instructions that a plain ARMv8.0 CPU
(Kryo 260 = Cortex-A73/A53, no LSE, no RCpc, no PAuth) cannot execute.

  scan-armv8.py PATH... [--json out.json]

Counted in the executable sections (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS):
  lse   ARMv8.1 atomic memory ops LDADD/LDCLR/LDEOR/LDSET/LD[SU]MAX/LD[SU]MIN/SWP (+ LDAPR*, same encoding group)
  cas   ARMv8.1 CAS/CASA/CASL/CASAL (byte..dword)
  casp  ARMv8.1 CASP pairs
  pac   ARMv8.3 PAC/AUT/RETA/BRA/BLRA/LDRA (the HINT-space PACIASP/AUTIASP are NOPs on v8.0 and are not counted)
Exit status 1 when lse+cas+casp+pac > 0 in any arm64 slice, so a CI step fails on the first bad build.
Same masks as strumenti/conta-lse.py (owner PC), extended to FAT files, CASP and non-HINT PAuth."""
import json
import os
import struct
import sys

ARM64 = 0x0100000C


def slices(data):
    magic = struct.unpack_from('>I', data)[0]
    if magic in (0xCAFEBABE, 0xCAFEBABF):
        count = struct.unpack_from('>I', data, 4)[0]
        for i in range(count):
            if magic == 0xCAFEBABE:
                cpu, sub, off, size, _ = struct.unpack_from('>iiIII', data, 8 + 20 * i)
            else:
                cpu, sub, off, size, _, _ = struct.unpack_from('>iiQQII', data, 8 + 32 * i)
            yield cpu & 0xFFFFFFFF, sub & 0xFFFFFFFF, data[off:off + size]
    elif struct.unpack_from('<I', data)[0] == 0xFEEDFACF:
        cpu, sub = struct.unpack_from('<II', data, 4)
        yield cpu, sub, data


def classify(w):
    if (w & 0x3F200C00) == 0x38200000:
        return 'lse'
    if (w & 0x3FA07C00) == 0x08A07C00:
        return 'cas'
    if (w & 0xBFA07C00) == 0x08207C00:
        return 'casp'
    # PAuth outside the HINT space: PACIA/PACIB/PACDA/... AUTIA/... XPACI/XPACD (data-processing 1 source, opcode2=1)
    if (w & 0xFFFFC000) == 0xDAC10000:
        return 'pac'
    # BRAA/BRAB/BLRAA/BLRAB/RETAA/RETAB/ERETAA/BRAAZ... (unconditional branch register with PAuth bits)
    if (w & 0xFE9FF800) == 0xD61F0800:
        return 'pac'
    # LDRAA/LDRAB
    if (w & 0xFF200400) == 0xF8200400:
        return 'pac'
    return None


def scan_slice(m):
    counts = dict(words=0, lse=0, cas=0, casp=0, pac=0)
    ncmds = struct.unpack_from('<I', m, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', m, off)
        if cmd == 0x19:
            nsects = struct.unpack_from('<I', m, off + 64)[0]
            for i in range(nsects):
                s = off + 72 + i * 80
                flags = struct.unpack_from('<I', m, s + 64)[0]
                if flags & 0x80000400:
                    sect_size, foff = struct.unpack_from('<QI', m, s + 40)
                    if foff == 0:
                        continue
                    for (w,) in struct.iter_unpack('<I', m[foff:foff + sect_size - sect_size % 4]):
                        counts['words'] += 1
                        kind = classify(w)
                        if kind:
                            counts[kind] += 1
        off += size
    return counts


def files_of(paths):
    for root in paths:
        if os.path.isfile(root):
            yield root, os.path.basename(root)
            continue
        for d, _, names in os.walk(root):
            for n in sorted(names):
                p = os.path.join(d, n)
                if not os.path.islink(p):
                    yield p, os.path.relpath(p, root)


def main(argv):
    out_json = None
    if '--json' in argv:
        i = argv.index('--json')
        out_json = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    results, bad = [], 0
    for path, rel in files_of(argv):
        with open(path, 'rb') as fh:
            head = fh.read(4)
            if head not in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf', b'\xcf\xfa\xed\xfe'):
                continue
            data = head + fh.read()
        for cpu, sub, m in slices(data):
            if cpu != ARM64:
                print(f'{rel}: cpu {cpu:#x} sub {sub:#x} (not arm64) skipped')
                results.append(dict(file=rel, cpu=cpu, skipped=True))
                continue
            c = scan_slice(m)
            if (sub & 0xFF) == 2:
                c['arm64e'] = True
            n = c['lse'] + c['cas'] + c['casp'] + c['pac']
            bad += n
            print(f"{rel}: arm64 sub {sub & 0xff:#x} words {c['words']} LSE {c['lse']} CAS {c['cas']} CASP {c['casp']} PAC {c['pac']}")
            results.append(dict(file=rel, sub=sub & 0xFF, **c))
    print(f'TOTAL ARMv8.1+ {bad} in {sum(1 for r in results if not r.get("skipped"))} arm64 slices')
    if out_json:
        with open(out_json, 'w') as fh:
            json.dump(dict(total=bad, slices=results), fh, indent=1)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
