"""IDA adapter. Load the raw image as a binary file with processor 8051, then
File > Script file. The flat segment is replaced by one segment per bank with
segment base N*0x10000, so the 8051 module resolves same-bank 16-bit targets
by itself; a segment translation to the common segment covers calls into it. Cross-bank references, inline call
arguments and function entries come from bank8051.analyze.

Untested in IDA itself: API names were checked against the IDAPython
documentation, the script was not run.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ida_auto
import ida_bytes
import ida_ida
import ida_loader
import ida_pro
import ida_segment
import ida_xref
from bank8051 import Layout, analyze, vectors

SEL, MASK = 0x9F, 0x07


def main():
    lo, hi = ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
    image = ida_bytes.get_bytes(lo, hi - lo)
    lay = Layout(len(image), sel=SEL, mask=MASK)
    read = lay.reader(image)
    res = analyze(read, lay, vectors(read, lay))

    while ida_segment.get_segm_qty():
        ida_segment.del_segm(ida_segment.getnseg(0).start_ea, ida_segment.SEGMOD_KILL)
    for bank, va, off, size in lay.slices():
        s = ida_segment.segment_t()
        s.start_ea, s.end_ea = va, va + size
        s.sel = ida_segment.setup_selector((bank * 0x10000) >> 4)
        s.bitness, s.type = 0, ida_segment.SEG_CODE
        s.perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC
        ida_segment.add_segm_ex(s, "bank%d" % bank, "CODE", ida_segment.ADDSEG_OR_DIE)
        ida_loader.mem2base(image[off:off + size], va, off)
        if bank:
            # calls from a bank into the common area resolve through the translation list
            ida_segment.set_segment_translations(va, ida_pro.eavec_t([0]))

    for va, size in res.inline:
        ida_bytes.create_byte(va, size, True)
    for e in res.edges:
        if e.native:
            continue
        kind = ida_xref.fl_CN if e.kind == "call" else ida_xref.fl_JN
        ida_xref.add_cref(e.src, e.dst, kind | ida_xref.XREF_USER)
        ida_bytes.set_cmt(e.src, "bank%d:0x%04x" % (lay.bank_of(e.dst) or 0, e.dst & 0xFFFF), 0)
    for va, why in res.unresolved:
        ida_bytes.set_cmt(va, "unresolved: " + why, 0)
    for f in res.functions:
        ida_auto.auto_make_proc(f)
    ida_auto.auto_wait()
    print("%d functions, %d edges (%d cross-bank), %d inline arguments, %d unresolved" % (
        len(res.functions), len(res.edges), sum(1 for e in res.edges if not e.native),
        len(res.inline), len(res.unresolved)))


main()
