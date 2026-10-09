# bank8051

Flow recovery for bank-switched 8051 firmware (CC2541, C8051F12x and the like):
one core, three adapters.

| file | role |
|---|---|
| `bank8051.py` | core: layout, emulator-driven disassembler, cross-bank resolution; no dependencies, Python 2.7 and 3 |
| `bank8051_r2.py` | radare2, through r2pipe; tested on the CC2541 images from `RedBearLab/CCLoader` |
| `bank8051_ghidra.py` | Ghidra script (Jython); overlays per bank; **not run in Ghidra** |
| `bank8051_ida.py` | IDAPython script; segment per bank; **not run in IDA** |

## Model

* Virtual addresses: common area at `0x0000..0x7FFF`, bank N window at
  `N*0x10000 + 0x8000`. Bank 0 in the window mirrors the common area.
* Each basic block is emulated by a small concrete 8051 interpreter. Only the
  bank select register is known at block start, from the block's own address.
  Calls and jumps into the common area are followed, so a trampoline of any
  shape is seen writing the select register and jumping. An edge found
  through a call is attributed to that call in the analysed block; one found
  through a jump to the instruction that actually transfers.
* A callee that pops its return address and reads bytes through `movc` is
  using inline arguments (IAR `?BCALL`): the bytes become data, flow continues
  after them.
* `jmp @A+DPTR` with known DPTR and unknown A over a table of `ljmp` is a
  switch; its cases become successors.
* Sweep: every `lcall`/`ljmp` to a trampoline discovered by flow, anywhere in
  the image, is tried as a function entry and kept if it resolves. This picks
  up code only reachable through function pointers.
* Unknown values stop a path. Unresolved computed transfers are reported with
  the instruction address; nothing is guessed.

Parameters: `sel` (bank select SFR, default `0x9F` = CC2541 FMAP), `mask`.
Only the symmetric layout (32 KB common, 32 KB window, bank N at file offset
N*0x8000) is modelled.

## radare2

```
pip install r2pipe
python3 bank8051_r2.py fw.bin -sel 0x9F -o fw.r2
r2 -n -a 8051 -i fw.r2 fw.bin
```

Result on the two CC2541 images (256 KB, 8 banks):

| image | functions | edges | cross-bank | inline args | unresolved | code coverage |
|---|---|---|---|---|---|---|
| Demo.bin | 2367 | 11410 | 2166 | 756 | 52 | 93% of non-0xFF bytes |
| CC2541hm10v540.bin | 2713 | 15423 | 2985 | 815 | 42 | 97% |

The unresolved ones are `jmp @A+DPTR` with a value from RAM or XDATA.

## Ghidra

Import the raw image with language `8051:BE:16:default`, run the script from
the Script Manager. Banks become overlay blocks; Ghidra maps a 16-bit target
outside an overlay's range to the base space, so same-bank jumps and calls
into the common area resolve by themselves.

## IDA

Load the image as binary with processor 8051, run the script. The flat
segment is replaced by one segment per bank with base `N*0x10000`; bank
segments get a segment translation to the common segment so calls into it
resolve.

## Limits

* Targets that depend on data from RAM or XDATA (task tables, callbacks) are
  reached only through the sweep, and only when their thunk is in the image.
* Interrupt handlers running with a bank selected elsewhere are analysed with
  an unknown bank in the common area.
* Inline data after a thunk makes the thunk "fall through" into the next one
  in the function model; references are right, function extents are coarse.
