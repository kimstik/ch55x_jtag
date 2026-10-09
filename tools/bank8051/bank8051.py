"""Bank-switched 8051 code: layout, flow recovery and cross-bank resolution.

Platform independent core used by the IDA, Ghidra and radare2 adapters.
Python 2.7 (Jython) and Python 3 compatible, no dependencies.

Virtual address scheme (one flat 24-bit space):
    common area     : 0x0000 .. COMMON-1
    bank N window   : N*0x10000 + COMMON .. N*0x10000 + 0xFFFF
Bank 0 selected in the window mirrors the common area (CC2541, C8051F12x).

The engine is a recursive-descent disassembler whose flow decisions are
taken by a small concrete emulator of straight-line 8051 code. Every basic
block starts with unknown registers except the bank select register, which
is known from the block's own address when the block lives in a window.
Calls into the common area are followed, that is where trampolines live:
the emulator sees the trampoline write the select register and jump, and
attributes the resulting edge to the call in the analysed block. Return
addresses popped and read with movc are recognised as inline arguments
(IAR ?BCALL style), so the bytes after such a call become data and flow
continues after them. Unknown values stop a path; nothing is guessed.
"""

LEN = (
    "1231121111111111"  # 0x
    "3231121111111111"  # 1x
    "3211221111111111"  # 2x
    "3211221111111111"  # 3x
    "2223221111111111"  # 4x
    "2223221111111111"  # 5x
    "2223221111111111"  # 6x
    "2221232222222222"  # 7x
    "2221132222222222"  # 8x
    "3221221111111111"  # 9x
    "2221112222222222"  # Ax
    "2221333333333333"  # Bx
    "2221121111111111"  # Cx
    "2221131122222222"  # Dx
    "1211121111111111"  # Ex
    "1211121111111111"  # Fx
)

ACC, B, DPL, DPH = 0xE0, 0xF0, 0x82, 0x83
COND = set([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0xD5]) | set(range(0xB4, 0xC0)) | set(range(0xD8, 0xE0))
MAX_DEPTH = 4
BUDGET = 4096
SWITCH_MAX = 128


def bit_addr(b):
    """Bit address -> (byte address, mask)."""
    byte = (b & 0xF8) if b >= 0x80 else 0x20 + (b >> 3)
    return byte, 1 << (b & 7)


class Layout(object):
    """Only the symmetric layout is modelled: the common area and the window
    are both 0x8000 bytes, bank N is at file offset N*0x8000, bank 0 in the
    window mirrors the common area. That is the CC2541 and C8051F12x layout."""

    def __init__(self, size, common=0x8000, sel=0x9F, mask=0x07):
        if common != 0x10000 - common:
            raise ValueError("only common == window == 0x8000 is supported")
        self.common, self.window, self.sel, self.mask = common, common, sel, mask
        self.nbanks = max(1, size // self.window)

    def va(self, bank, addr):
        """16-bit code address as seen with `bank` selected -> virtual address."""
        if addr < self.common:
            return addr
        if bank == 0:
            return addr - self.common
        return bank * 0x10000 + addr

    def bank_of(self, va):
        """Bank a virtual address lives in; None for the common area."""
        return None if va < self.common else va >> 16

    def slices(self):
        """(bank, va, file offset, size) for every region to map."""
        out = [(0, 0, 0, self.common)]
        for n in range(1, self.nbanks):
            out.append((n, n * 0x10000 + self.common, n * self.window, self.window))
        return out

    def reader(self, image):
        """read(va, n) over the raw image (bytes, bytearray or list of ints)."""
        image = bytearray(image)

        def read(va, n):
            for bank, start, off, size in self.slices():
                if start <= va and va + n <= start + size:
                    return list(image[va - start + off:va - start + off + n])
            return None
        return read


class Edge(tuple):
    """(src va, dst va, kind, native).

    kind   : "call" or "jmp", by the instruction at src.
    native : plain 16-bit target in the same bank as src, no bank change.
             IDA and Ghidra (cip-51) resolve these themselves, radare2 does not.
    """
    src = property(lambda s: s[0])
    dst = property(lambda s: s[1])
    kind = property(lambda s: s[2])
    native = property(lambda s: s[3])


class Frame(object):
    """A followed call: where to come back, and what it reads inline."""

    def __init__(self, entry, ret, origin, ram, stack):
        self.entry, self.ret, self.origin, self.ram, self.stack = entry, ret, origin, ram, stack
        self.skip = 0


class Block(object):
    def __init__(self, start):
        self.start, self.end = start, start
        self.succ = []        # va of following blocks in the same function
        self.edges = []       # Edge
        self.inline = []      # (va, size) data bytes inside the block
        self.unresolved = []  # (va, reason)
        self.tramps = set()   # common functions that switched bank on this block's behalf


class Emu(object):
    """Decodes one basic block, emulating it to decide where flow goes."""

    def __init__(self, read, layout, starts):
        self.read = read      # read(va, n) -> list of ints, or None
        self.lay = layout
        self.starts = starts  # known block starts: a block ends when it runs into one

    def run(self, start):
        self.blk = Block(start)
        self.ram = {self.lay.sel: self.lay.bank_of(start)}
        self.carry = None
        self.stack, self.frames = [], []
        self.left = False     # followed a jump out of the block
        self.pc = start
        for _ in range(BUDGET):
            if self.top() and self.pc != start and self.pc in self.starts:
                self.blk.succ.append(self.pc)
                break
            op = self.read(self.pc, 1)
            if not op:
                break
            n = int(LEN[op[0]])
            ins = self.read(self.pc, n)
            if not ins or len(ins) < n:
                break
            if self.top():
                self.blk.end = self.pc + n
            if not self.step(ins):
                break
        return self.blk

    # -- helpers ---------------------------------------------------------------

    def top(self):
        """Still decoding the analysed block itself."""
        return not self.frames and not self.left

    def get(self, a):
        return self.ram.get(a)

    def set(self, a, v):
        self.ram[a] = v

    def clobber(self):
        for a in [ACC, B, DPL, DPH] + list(range(8)):
            self.ram[a] = None
        self.carry = None

    def here(self):
        return self.frames[0].origin if self.frames else self.cur

    def near(self, addr16):
        """Target of a relative or same-bank jump from the current instruction."""
        if addr16 < self.lay.common:
            return addr16
        bank = self.lay.bank_of(self.cur)
        return None if bank is None else self.lay.va(bank, addr16)

    def edge(self, addr16, kind):
        """Control reaches window address `addr16`: record the edge, return dst."""
        src, bank = self.here(), self.get(self.lay.sel)
        if bank is None:
            self.blk.unresolved.append((src, "bank unknown"))
            return None
        dst = self.lay.va(bank & self.lay.mask, addr16)
        if self.frames:
            kind = "call"  # reached through a call of the analysed block
            self.blk.tramps.update(f.entry for f in self.frames)
        native = not self.frames and self.lay.bank_of(src) is not None \
            and self.lay.bank_of(dst) == self.lay.bank_of(src)
        self.blk.edges.append(Edge((src, dst, kind, native)))
        return dst

    def resume(self, f):
        """Continue after the call that opened frame `f`, callee effects unknown."""
        self.ram, self.stack = f.ram, f.stack
        self.clobber()
        self.pc = f.ret + f.skip
        return True

    def unwind(self):
        """Give up on the current path: back to the last followed call site."""
        if not self.frames:
            return False
        f = self.frames.pop()
        if f.skip:
            self.blk.inline.append((f.ret, f.skip))
        return self.resume(f)

    def leave(self):
        """The path went into a bank: every followed call is a transfer, not a
        return. Continue after the call in the analysed block."""
        if not self.frames:
            return False
        for f in self.frames:
            if f.skip:
                self.blk.inline.append((f.ret, f.skip))
        f, self.frames = self.frames[0], []
        return self.resume(f)

    def jump(self, addr16):
        if addr16 >= self.lay.common:
            dst = self.edge(addr16, "jmp")
            if self.top() and dst is not None and self.blk.edges[-1].native:
                self.blk.succ.append(dst)
            return self.leave()
        if self.top():
            self.blk.succ.append(addr16)
            self.left = True
        self.pc = addr16
        return True

    def call(self, addr16, nxt):
        if addr16 >= self.lay.common or len(self.frames) >= MAX_DEPTH:
            if addr16 >= self.lay.common:
                self.edge(addr16, "call")
            self.clobber()
            return True
        if not self.frames:
            self.blk.edges.append(Edge((self.cur, addr16, "call", True)))
        self.frames.append(Frame(addr16, nxt, self.here(), dict(self.ram), list(self.stack)))
        self.stack += [nxt & 0xFF, (nxt >> 8) & 0xFF]
        self.pc = addr16
        return True

    def switch(self, table16):
        """jmp @A+DPTR with unknown A over a table of ljmp: collect the cases."""
        bank = self.get(self.lay.sel)
        if table16 >= self.lay.common and bank is None:
            self.blk.unresolved.append((self.here(), "bank unknown"))
            return
        base = self.lay.va((bank or 0) & self.lay.mask, table16)
        found = 0
        for i in range(SWITCH_MAX):
            e = self.read(base + 3 * i, 3)
            if not e or e[0] != 0x02:
                break
            dst = self.near(e[1] << 8 | e[2])
            if dst is not None:
                self.blk.succ.append(dst)
                found += 1
        if not found:
            self.blk.unresolved.append((self.here(), "A/DPTR unknown"))

    # -- instruction semantics ---------------------------------------------------

    def step(self, ins):
        op, nxt = ins[0], self.pc + len(ins)
        self.cur, self.pc = self.pc, nxt

        if op in COND:
            if self.top():
                rel = ins[-1] - (0x100 if ins[-1] > 0x7F else 0)
                t = self.near((nxt + rel) & 0xFFFF)
                self.blk.succ += [nxt] + ([t] if t is not None else [])
            return self.unwind()
        if op == 0x02:
            return self.jump(ins[1] << 8 | ins[2])
        if op == 0x12:
            return self.call(ins[1] << 8 | ins[2], nxt)
        if (op & 0x1F) == 0x01:
            return self.jump((nxt & 0xF800) | (op >> 5) << 8 | ins[1])
        if (op & 0x1F) == 0x11:
            return self.call((nxt & 0xF800) | (op >> 5) << 8 | ins[1], nxt)
        if op == 0x80:
            return self.jump((nxt + ins[1] - (0x100 if ins[1] > 0x7F else 0)) & 0xFFFF)
        if op == 0x73:  # jmp @A+DPTR
            a, l, h = self.get(ACC), self.get(DPL), self.get(DPH)
            if l is not None and h is not None and a is None and self.top():
                self.switch(h << 8 | l)
                return False
            if a is None or l is None or h is None:
                self.blk.unresolved.append((self.here(), "A/DPTR unknown"))
                return self.unwind()
            return self.jump((a + (h << 8 | l)) & 0xFFFF)
        if op in (0x22, 0x32):  # ret / reti: a return, or a jump to a pushed address
            if len(self.stack) < 2:
                return self.unwind()
            h, l = self.stack.pop(), self.stack.pop()
            if h is None or l is None:
                return self.unwind()
            t = h << 8 | l
            if self.frames and t == (self.frames[-1].ret & 0xFFFF):
                f = self.frames.pop()
                self.pc = f.ret
                return True
            if self.frames and t < self.lay.common:
                # dispatched into the common area (bank byte 0): a transfer too
                self.blk.edges.append(Edge((self.here(), t, "call", False)))
                self.blk.tramps.update(f.entry for f in self.frames)
                return self.leave()
            return self.jump(t)

        # data movement
        if op == 0x74:
            self.set(ACC, ins[1])
        elif op == 0x75:
            self.set(ins[1], ins[2])
        elif op & 0xF8 == 0x78:
            self.set(op & 7, ins[1])
        elif op == 0x90:
            self.set(DPH, ins[1])
            self.set(DPL, ins[2])
        elif op == 0xE4:
            self.set(ACC, 0)
        elif op == 0xE5:
            self.set(ACC, self.get(ins[1]))
        elif op == 0xF5:
            self.set(ins[1], self.get(ACC))
        elif op & 0xF8 == 0xE8:
            self.set(ACC, self.get(op & 7))
        elif op & 0xF8 == 0xF8:
            self.set(op & 7, self.get(ACC))
        elif op == 0x85:
            self.set(ins[2], self.get(ins[1]))
        elif op & 0xF8 == 0xA8:
            self.set(op & 7, self.get(ins[1]))
        elif op & 0xF8 == 0x88:
            self.set(ins[1], self.get(op & 7))
        elif op == 0xC0:
            self.stack.append(self.get(ins[1]))
        elif op == 0xD0:
            self.set(ins[1], self.stack.pop() if self.stack else None)
        elif op == 0xA3:
            l, h = self.get(DPL), self.get(DPH)
            if l is not None and h is not None:
                v = ((h << 8 | l) + 1) & 0xFFFF
                self.set(DPH, v >> 8)
                self.set(DPL, v & 0xFF)
        elif op in (0x83, 0x93):  # movc: table reads from code, inline arguments
            a, l, h, bank = self.get(ACC), self.get(DPL), self.get(DPH), self.get(self.lay.sel)
            if op == 0x83:
                l, h, bank = nxt & 0xFF, (nxt >> 8) & 0xFF, self.lay.bank_of(self.cur) or 0
            v = None
            if a is not None and l is not None and h is not None:
                t = (a + (h << 8 | l)) & 0xFFFF
                if bank is not None or t < self.lay.common:  # common needs no bank
                    r = self.read(self.lay.va((bank or 0) & self.lay.mask, t), 1)
                    v = r[0] if r else None
                for f in self.frames:
                    if 0 <= t - (f.ret & 0xFFFF) < 8:
                        f.skip = max(f.skip, t - (f.ret & 0xFFFF) + 1)
            self.set(ACC, v)
        # bit and logic ops on direct bytes (port-pin bank selects)
        elif op in (0xC2, 0xD2, 0xB2, 0x92):
            byte, m = bit_addr(ins[1])
            v = self.get(byte)
            if v is None or (op == 0x92 and self.carry is None):
                self.set(byte, None)
            else:
                self.set(byte, {0xC2: v & ~m, 0xD2: v | m, 0xB2: v ^ m,
                                0x92: (v | m) if self.carry else (v & ~m)}[op] & 0xFF)
        elif op == 0xC3:
            self.carry = 0
        elif op == 0xD3:
            self.carry = 1
        elif op in (0x43, 0x53, 0x63):
            v = self.get(ins[1])
            self.set(ins[1], None if v is None else {0x43: v | ins[2], 0x53: v & ins[2], 0x63: v ^ ins[2]}[op])
        elif op in (0x42, 0x52, 0x62):
            v, a = self.get(ins[1]), self.get(ACC)
            self.set(ins[1], None if v is None or a is None else {0x42: v | a, 0x52: v & a, 0x62: v ^ a}[op])
        elif op in (0x44, 0x54, 0x64):
            a = self.get(ACC)
            self.set(ACC, None if a is None else {0x44: a | ins[1], 0x54: a & ins[1], 0x64: a ^ ins[1]}[op])
        else:
            # anything else may touch A, C and a direct operand
            self.set(ACC, None)
            self.carry = None
            if op in (0x05, 0x15, 0xC5, 0x86, 0x87):
                self.set(ins[1], None)
            if op & 0xF8 in (0x08, 0x18, 0xC8):
                self.set(op & 7, None)
            if op in (0x84, 0xA4):
                self.set(B, None)
        return True


class Result(object):
    def __init__(self):
        self.functions = {}   # entry va -> sorted block start list
        self.blocks = {}      # start va -> Block
        self.edges = set()    # Edge, every call plus every non-native jump
        self.inline = set()   # (va, size)
        self.unresolved = []  # (va, reason), only where no path resolved


def callers(read, layout, targets):
    """Every lcall/ljmp in the image whose 16-bit target is in `targets`."""
    out = []
    for bank, start, off, size in layout.slices():
        data = read(start, size) or []
        for i in range(len(data) - 2):
            if data[i] in (0x02, 0x12) and (data[i + 1] << 8 | data[i + 2]) in targets:
                out.append(start + i)
    return out


def analyze(read, layout, roots, sweep=True):
    """Recover functions, blocks and bank edges reachable from `roots`.

    With `sweep`, once the trampolines are known from the flow, every call
    to one of them anywhere in the image that flow did not reach is tried
    as a function entry and kept if it resolves. That picks up code only
    reachable through function pointers (task tables, callbacks).
    """
    res = Result()
    emu = Emu(read, layout, res.blocks)
    unres, entries, tramps, covered = set(), set(), set(), set()
    work = list(roots)

    def take(blk):
        res.blocks[blk.start] = blk
        covered.update(range(blk.start, blk.end))
        res.inline.update(blk.inline)
        unres.update(blk.unresolved)
        tramps.update(blk.tramps)
        work.extend(blk.succ)
        for e in blk.edges:
            res.edges.add(e)
            if e.kind == "call" or not e.native:
                work.append(e.dst)
                entries.add(e.dst)

    swept = set()
    while work or (sweep and tramps - swept):
        while work:
            b = work.pop()
            if b not in res.blocks:
                take(emu.run(b))
        if sweep:
            swept = set(tramps)
            for va in callers(read, layout, swept):
                if va not in covered and va not in res.blocks:
                    blk = emu.run(va)
                    if any(not e.native for e in blk.edges):
                        take(blk)
                        entries.add(va)
    # a block that runs into a later block start ends there
    starts = sorted(res.blocks)
    for i in range(len(starts) - 1):
        blk = res.blocks[starts[i]]
        if blk.end > starts[i + 1]:
            blk.end, blk.succ = starts[i + 1], [starts[i + 1]]
    for f in set(roots) | entries:
        mine, bwork = set(), [f]
        while bwork:
            b = bwork.pop()
            if b not in mine:
                mine.add(b)
                bwork += res.blocks[b].succ
        res.functions[f] = sorted(mine)
    # trampolines analysed on their own cannot know A/DPTR: not worth reporting
    noise = set()
    for t in tramps:
        for b in res.functions.get(t, []):
            noise.update(range(b, res.blocks[b].end))
    done = set(e.src for e in res.edges if not e.native)
    res.unresolved = sorted(u for u in unres if u[0] not in done and u[0] not in noise)
    return res


def vectors(read, layout):
    """Reset and interrupt vectors that hold an ljmp."""
    return [v for v in [0] + list(range(3, 0x100, 8)) if (read(v, 1) or [0])[0] == 0x02]
