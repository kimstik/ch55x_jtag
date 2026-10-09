#!/usr/bin/env python3
"""radare2 adapter.

    python3 bank8051_r2.py firmware.bin [-sel 0x9F] [-common 0x8000] [-window 0x8000] [-mask 7] [-o out.r2]

Maps the image bank by bank, then writes the functions, basic blocks, code
references and inline data the core recovers. radare2's own 8051 analysis
is not used: it resolves 16-bit targets flat, which is wrong inside a bank
window. With -o the commands are saved as an r2 script to replay later:
    r2 -n -a 8051 -i out.r2 firmware.bin
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import r2pipe
from bank8051 import Layout, analyze, vectors


def name(lay, va):
    bank = lay.bank_of(va)
    return "fcn.%04x" % va if bank is None else "fcn.b%d.%04x" % (bank, va & 0xFFFF)


def main(argv):
    path, opt = argv[0], dict(zip(argv[1::2], argv[2::2]))
    num = lambda k, d: int(opt.get(k, d), 0)
    lay = Layout(os.path.getsize(path), num("-common", "0x8000"), num("-window", "0x8000"),
                 num("-sel", "0x9F"), num("-mask", "7"))
    r2 = r2pipe.open(path, flags=["-n", "-N", "-a", "8051", "-e", "scr.color=0"])
    log = []

    def cmd(c):
        log.append(c)
        return r2.cmd(c)

    with open(path, "rb") as f:
        read = lay.reader(f.read())

    cmd("om-*")
    for bank, va, off, size in lay.slices():
        cmd("om 3 0x%x 0x%x 0x%x rx bank%d" % (va, size, off, bank))

    res = analyze(read, lay, vectors(read, lay))

    for va, size in sorted(res.inline):
        cmd("Cd %d @ 0x%x" % (size, va))
    for f, blocks in sorted(res.functions.items()):
        cmd("af+ 0x%x %s" % (f, name(lay, f)))
        for b in blocks:
            blk = res.blocks[b]
            cmd("afb+ 0x%x 0x%x %d %s" % (f, b, blk.end - b, " ".join("0x%x" % s for s in blk.succ[:2])))
            for s in blk.succ[2:]:
                cmd("axc 0x%x @ 0x%x" % (s, blk.end - 1))
    for e in sorted(res.edges):
        cmd("ax%s 0x%x @ 0x%x" % ("C" if e.kind == "call" else "c", e.dst, e.src))
        if not e.native:
            cmd("CCu bank%d:0x%04x @ 0x%x" % (lay.bank_of(e.dst) or 0, e.dst & 0xFFFF, e.src))
    for va, why in res.unresolved:
        cmd("CCu unresolved: %s @ 0x%x" % (why, va))

    cross = sum(1 for e in res.edges if not e.native)
    print("%d functions, %d blocks, %d edges (%d cross-bank), %d inline arguments, %d unresolved" % (
        len(res.functions), len(res.blocks), len(res.edges), cross, len(res.inline), len(res.unresolved)))
    for va, why in res.unresolved:
        print("  unresolved 0x%06x: %s" % (va, why))
    if "-o" in opt:
        with open(opt["-o"], "w") as f:
            f.write("\n".join(log) + "\n")
    r2.quit()


if __name__ == "__main__":
    main(sys.argv[1:])
