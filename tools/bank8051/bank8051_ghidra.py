# Bank-switched 8051: rebuild memory as overlays and write what the core resolves.
# Import the raw image with language 8051:BE:16:default (one block at 0), then run.
# @category 8051
#
# Each bank window becomes an overlay block "bankN" at 0x8000..0xFFFF. Ghidra
# maps a 16-bit target outside an overlay's range to the base space, so a call
# into the common area from a bank and a jump inside the same bank both resolve
# without help (OverlayAddressSpace.getAddress). Cross-bank edges, inline call
# arguments and function entries come from bank8051.analyze.
#
# Untested in Ghidra itself: API names were checked against the Ghidra sources,
# the script was not run.
import os
import sys

try:
    HERE = os.path.dirname(os.path.abspath(__file__))
except NameError:
    HERE = getSourceFile().getParentFile().getAbsolutePath()
sys.path.insert(0, HERE)
import jarray
from ghidra.program.model.symbol import RefType, SourceType
from bank8051 import Layout, analyze, vectors

SEL, MASK = 0x9F, 0x07


def main():
    mem = currentProgram.getMemory()
    blocks = list(mem.getBlocks())
    if len(blocks) != 1:
        popup("Expected exactly one memory block holding the raw image")
        return
    image = [b & 0xFF for b in getBytes(blocks[0].getStart(), int(blocks[0].getSize()))]
    lay = Layout(len(image), sel=SEL, mask=MASK)
    read = lay.reader(image)
    res = analyze(read, lay, vectors(read, lay))

    mem.removeBlock(blocks[0], monitor)
    space = {}
    for bank, va, off, size in lay.slices():
        raw = jarray.array([x - 256 if x > 127 else x for x in image[off:off + size]], "b")
        blk = createMemoryBlock("bank%d" % bank, toAddr(va & 0xFFFF), raw, bank != 0)
        blk.setExecute(True)
        space[bank] = blk.getStart().getAddressSpace()

    def addr(va):
        bank = lay.bank_of(va)
        return toAddr(va) if bank is None else space[bank].getAddress(va & 0xFFFF)

    for va, size in res.inline:
        for i in range(size):
            createByte(addr(va + i))
    refs = currentProgram.getReferenceManager()
    for e in res.edges:
        if e.native or (lay.bank_of(e.dst) or 0) >= lay.nbanks:
            continue
        kind = RefType.UNCONDITIONAL_CALL if e.kind == "call" else RefType.UNCONDITIONAL_JUMP
        refs.addMemoryReference(addr(e.src), addr(e.dst), kind, SourceType.USER_DEFINED, 0)
        setEOLComment(addr(e.src), "bank%d:0x%04x" % (lay.bank_of(e.dst) or 0, e.dst & 0xFFFF))
    for va, why in res.unresolved:
        setEOLComment(addr(va), "unresolved: " + why)
    for f in sorted(res.functions):
        disassemble(addr(f))
        createFunction(addr(f), None)
    println("%d functions, %d edges (%d cross-bank), %d inline arguments, %d unresolved" % (
        len(res.functions), len(res.edges), sum(1 for e in res.edges if not e.native),
        len(res.inline), len(res.unresolved)))


main()
