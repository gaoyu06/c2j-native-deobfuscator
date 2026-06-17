#!/usr/bin/env python3
"""
j2c_emu - emulation-based recovery for the "Java -> C/C++ via JNI" obfuscator
family (native-obfuscator, j2cc, derivatives).

It runs the obfuscated native blob under a CPU emulator (Unicorn) with a mock JNI
environment, so it observes the C-rewritten logic that JNI tracing cannot:

  * recover  - list every native method (name, sig, fnPtr). Auto-discovers entry
               points: Java_* export symbols -> JNI_OnLoad emulation (with a mock
               JavaVM) -> explicit --registrar / --binary-json (j2cc regc style).
  * strings  - emulate a method and dump its decrypted string constants
               (the <clinit> XOR string table).
  * call     - oracle: invoke a native method as a pure function.

Generality: rests on the JVM-fixed JNI ABI, not on any obfuscator's choices.
Backends: x86-64  PE/Win64  and  ELF/System-V.  (Unicorn supports more arches;
add an ABI/Fmt pair to extend.)

Requires: unicorn   (pip install unicorn)
"""
import argparse, json, re, struct, sys

try:
    from unicorn import *
    from unicorn.x86_const import *
except ImportError:
    sys.exit("need unicorn:  python -m pip install unicorn")

NUL = bytes([0])

# ---- canonical JNI function-table indices (offset = index*8) -------------
JNI = dict(
    AllocObject=27, GetObjectClass=31, IsInstanceOf=32, GetMethodID=33,
    CallObjectMethod=34, CallBooleanMethod=37, CallIntMethod=49,
    CallVoidMethod=61, CallNonvirtualObjectMethod=88, CallNonvirtualVoidMethod=91,
    GetFieldID=94, GetObjectField=95, GetIntField=100,
    GetStaticMethodID=113, CallStaticObjectMethod=114, CallStaticVoidMethod=141,
    GetStaticFieldID=144, GetStaticObjectField=145, SetStaticObjectField=154,
    NewString=163, GetStringLength=164, GetStringChars=165, NewStringUTF=167,
    GetStringUTFLength=168, GetStringUTFChars=169, GetArrayLength=171,
    NewObjectArray=172, NewByteArray=176, NewCharArray=177, NewIntArray=179,
    GetByteArrayRegion=200, GetCharArrayRegion=201, GetIntArrayRegion=203,
    SetByteArrayRegion=208, SetCharArrayRegion=209, SetIntArrayRegion=211,
    RegisterNatives=215, ExceptionOccurred=15, ExceptionClear=17,
    ExceptionCheck=228, GetStringRegion=220, GetStringUTFRegion=221,
)
IDX2NAME = {v: k for k, v in JNI.items()}
# JavaVM (invocation interface) table: GetEnv=6, AttachCurrentThread=4
JVM_GETENV, JVM_ATTACH = 6, 4


# ============================ ABIs ===================================
class ABI:
    """Argument access for a calling convention (1-based; arg1 = JNIEnv*)."""
    regs = ()          # ordered integer arg registers
    shadow = 0         # bytes of shadow space before first stacked arg

    def arg(self, uc, rsp_entry, i):
        if i <= len(self.regs):
            return uc.reg_read(self.regs[i - 1])
        # stacked arg: after return address (+8) and shadow space
        off = rsp_entry + 8 + self.shadow + (i - len(self.regs) - 1) * 8
        return struct.unpack("<Q", uc.mem_read(off, 8))[0]

    def set_args(self, uc, args):
        for i, a in enumerate(args[:len(self.regs)]):
            uc.reg_write(self.regs[i], a)


class Win64(ABI):
    name = "win64"
    regs = (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)
    shadow = 0x20


class SysV(ABI):
    name = "sysv"
    regs = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
            UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9)
    shadow = 0


# ============================ Loaders ================================
class Fmt:
    """Parsed object file: sections, imports (slot->name), exports (name->va)."""
    def __init__(self, data):
        self.data = data
        self.base = 0
        self.sections = []          # (va, bytes)
        self.imports = {}           # slot_va -> symbol name (GOT/IAT)
        self.exports = {}           # name -> va
        self.parse()

    @staticmethod
    def detect(data):
        if data[:2] == b"MZ":
            return PE(data)
        if data[:4] == b"\x7fELF":
            return ELF(data)
        sys.exit("unrecognized object format (need PE 'MZ' or ELF)")


class PE(Fmt):
    abi = Win64()

    def parse(self):
        d = self.data
        e = struct.unpack_from("<I", d, 0x3c)[0]
        coff = e + 4
        nsec = struct.unpack_from("<H", d, coff + 2)[0]
        optsz = struct.unpack_from("<H", d, coff + 16)[0]
        opt = coff + 20
        self.base = struct.unpack_from("<Q", d, opt + 24)[0]
        secs = []
        so = opt + optsz
        for i in range(nsec):
            o = so + i * 40
            vs, va, rs, rp = struct.unpack_from("<IIII", d, o + 8)
            secs.append((va, vs, rp, rs))
            self.sections.append((self.base + va, d[rp:rp + rs]))
        self._secs = secs
        # imports
        imp_rva = struct.unpack_from("<II", d, opt + 112 + 8)[0]
        if imp_rva:
            o = self._rva(imp_rva)
            while True:
                OFT, _, _, NAME, FT = struct.unpack_from("<IIIII", d, o); o += 20
                if NAME == 0 and FT == 0:
                    break
                lo = self._rva(OFT or FT); j = 0
                while True:
                    ent = struct.unpack_from("<Q", d, lo + j * 8)[0]
                    if ent == 0:
                        break
                    if not (ent & (1 << 63)):
                        hn = self._rva(ent & 0x7fffffff)
                        self.imports[self.base + FT + j * 8] = \
                            d[hn + 2:].split(NUL)[0].decode("latin1")
                    j += 1
        # exports
        exp_rva = struct.unpack_from("<II", d, opt + 112)[0]
        if exp_rva:
            o = self._rva(exp_rva)
            nfun, nnames = struct.unpack_from("<II", d, o + 20)[0], struct.unpack_from("<I", d, o + 24)[0]
            addr_funcs = struct.unpack_from("<I", d, o + 28)[0]
            addr_names = struct.unpack_from("<I", d, o + 32)[0]
            addr_ords = struct.unpack_from("<I", d, o + 36)[0]
            for k in range(nnames):
                nrva = struct.unpack_from("<I", d, self._rva(addr_names) + k * 4)[0]
                name = d[self._rva(nrva):].split(NUL)[0].decode("latin1")
                ordi = struct.unpack_from("<H", d, self._rva(addr_ords) + k * 2)[0]
                frva = struct.unpack_from("<I", d, self._rva(addr_funcs) + ordi * 4)[0]
                self.exports[name] = self.base + frva

    def _rva(self, rva):
        for va, vs, rp, rs in self._secs:
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va)


class ELF(Fmt):
    abi = SysV()

    def parse(self):
        d = self.data
        is64 = d[4] == 2
        assert is64, "only ELF64 supported"
        (e_entry, e_phoff, e_shoff) = struct.unpack_from("<QQQ", d, 24)
        e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)
        # choose a load base for PIC objects (vaddr 0)
        min_va = min((struct.unpack_from("<Q", d, e_phoff + i * e_phentsize + 16)[0]
                      for i in range(e_phnum)
                      if struct.unpack_from("<I", d, e_phoff + i * e_phentsize)[0] == 1),
                     default=0)
        self.base = 0x10000000 if min_va == 0 else 0
        # map PT_LOAD segments; remember (vaddr, off, filesz) for vaddr->file xlat
        dynoff = None
        self._segs = []
        for i in range(e_phnum):
            p = e_phoff + i * e_phentsize
            p_type, _, p_off, p_va, _, p_filesz, p_memsz, _ = struct.unpack_from("<IIQQQQQQ", d, p)
            if p_type == 1:  # PT_LOAD
                seg = bytearray(d[p_off:p_off + p_filesz])
                seg += bytes(p_memsz - p_filesz)
                self.sections.append((self.base + p_va, bytes(seg)))
                self._segs.append((p_va, p_off, p_filesz))
            elif p_type == 2:  # PT_DYNAMIC
                dynoff = self._fileoff(p_va) if p_va else p_off
        # parse .dynamic
        dyn = {}
        if dynoff is not None:
            o = dynoff
            while True:
                tag, val = struct.unpack_from("<qQ", d, o); o += 16
                if tag == 0:
                    break
                dyn[tag] = val
        strtab_va = dyn.get(5)
        symtab_va = dyn.get(6)
        self._dynstr = self._fileoff(strtab_va)       # DT_STRTAB (file off)
        symtab = self._fileoff(symtab_va)             # DT_SYMTAB (file off)
        syment = dyn.get(11, 24)
        nsym = self._symcount(dyn) or (
            (strtab_va - symtab_va) // syment if (strtab_va and symtab_va
             and strtab_va > symtab_va) else 2000)
        self._syms = []
        for k in range(nsym):
            so = symtab + k * syment
            if so + syment > len(d):
                break
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from("<IBBHQQ", d, so)
            name = self._cstr(self._dynstr + st_name) if self._dynstr else ""
            self._syms.append((name, st_value, st_shndx))
            if name and st_value and st_shndx != 0:
                self.exports[name] = self.base + st_value
        # relocations -> imports (JUMP_SLOT / GLOB_DAT) and RELATIVE fixups
        for rtag, sztag, entsz in ((23, 2, 24), (7, 8, 24)):   # JMPREL/sz, RELA/sz
            ra = self._fileoff(dyn.get(rtag))
            rsz = dyn.get(sztag, 0)
            if ra is None:
                continue
            for off in range(ra, ra + rsz, entsz):
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", d, off)
                rtype = r_info & 0xffffffff
                rsym = r_info >> 32
                if rtype == 8:  # R_X86_64_RELATIVE -> *(base+off) = base+addend
                    self._patch(self.base + r_offset, self.base + r_addend)
                elif rtype in (6, 7):  # GLOB_DAT / JUMP_SLOT
                    nm = self._syms[rsym][0] if rsym < len(self._syms) else ""
                    self.imports[self.base + r_offset] = nm   # filled with sentinel later

    def _fileoff(self, va):
        if va is None:
            return None
        for p_va, p_off, p_filesz in getattr(self, "_segs", []):
            if p_va <= va < p_va + p_filesz:
                return p_off + (va - p_va)
        return va     # before segments parsed (DT scan) or 1:1 fallback

    def _symcount(self, dyn):
        d = self.data
        h = self._fileoff(dyn.get(4))                  # DT_HASH: nbucket, nchain
        if h is not None:
            return struct.unpack_from("<I", d, h + 4)[0]
        gh = self._fileoff(dyn.get(0x6ffffef5))        # DT_GNU_HASH
        if gh is None:
            return 0
        nbuckets, symoffset, bloom_sz, _ = struct.unpack_from("<IIII", d, gh)
        buckets_off = gh + 16 + bloom_sz * 8
        buckets = [struct.unpack_from("<I", d, buckets_off + i * 4)[0] for i in range(nbuckets)]
        last = max(buckets) if buckets else 0
        if last < symoffset:
            return symoffset
        chain_off = buckets_off + nbuckets * 4
        i = last
        while True:
            hv = struct.unpack_from("<I", d, chain_off + (i - symoffset) * 4)[0]
            if hv & 1:
                break
            i += 1
        return i + 1

    def _cstr(self, off):
        e = self.data.find(NUL, off)
        return self.data[off:e].decode("latin1", "replace")

    def _patch(self, va, value):
        # store fixup to apply after mapping (sections are immutable tuples now)
        self.__dict__.setdefault("_fixups", []).append((va, value))


# ============================ Emulator ===============================
class Emu:
    STACK = 0x200000000
    HEAP = 0x300000000
    ENV = 0x400000000
    VT = ENV + 0x1000
    STUB = 0x500000000
    RET = 0x600000000
    CRT = 0x700000000
    HBASE = 0x800000000
    JVM = 0x900000000
    JVMVT = JVM + 0x1000
    JVMSTUB = 0xa00000000

    def __init__(self, path, statics=None, verbose=False):
        self.fmt = Fmt.detect(open(path, "rb").read())
        self.abi = self.fmt.abi
        self.verbose = verbose
        self.statics = statics or {}
        self.methods = []
        self.cstrings = []
        self.handles = {}
        self.fill_order = []
        self.hnext = self.HBASE + 0x100
        self.allocs = []
        self._setup()

    def _setup(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        # map image
        lo = min(va for va, _ in self.fmt.sections)
        hi = max(va + len(b) for va, b in self.fmt.sections)
        page = 0x1000
        mlo = lo & ~(page - 1)
        msz = ((hi - mlo) + 0xffff) & ~0xffff
        uc.mem_map(mlo, msz)
        for va, b in self.fmt.sections:
            if b:
                uc.mem_write(va, b)
        for base, sz in ((self.STACK, 0x800000), (self.HEAP, 0x8000000),
                         (self.ENV, 0x40000), (self.STUB, 0x10000),
                         (self.RET, 0x1000), (self.CRT, 0x1000),
                         (self.HBASE, 0x2000000), (self.JVM, 0x2000),
                         (self.JVMSTUB, 0x1000)):
            uc.mem_map(base, sz)
        uc.reg_write(UC_X86_REG_RSP, self.STACK + 0x800000 - 0x40000)
        # JNIEnv -> vtable -> per-index stub
        uc.mem_write(self.ENV, struct.pack("<Q", self.VT))
        for i in range(400):
            uc.mem_write(self.VT + i * 8, struct.pack("<Q", self.STUB + i * 8))
        # JavaVM -> vtable -> per-index stub
        uc.mem_write(self.JVM, struct.pack("<Q", self.JVMVT))
        for i in range(16):
            uc.mem_write(self.JVMVT + i * 8, struct.pack("<Q", self.JVMSTUB + i * 8))
        # imports (malloc/calloc/free) -> CRT sentinels
        self.crt = {}
        si = 0
        for slot, nm in self.fmt.imports.items():
            if nm in ("malloc", "calloc", "free"):
                s = self.CRT + si * 8; si += 1
                try:
                    uc.mem_write(slot, struct.pack("<Q", s)); self.crt[s] = nm
                except UcError:
                    pass
        # apply ELF RELATIVE fixups
        for va, val in getattr(self.fmt, "_fixups", []):
            try:
                uc.mem_write(va, struct.pack("<Q", val))
            except UcError:
                pass
        uc.hook_add(UC_HOOK_CODE, self._hook)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                    UC_HOOK_MEM_FETCH_UNMAPPED, self._unmapped)
        self.uc = uc

    # ---- handles --------------------------------------------------------
    def _malloc(self, n):
        p = (self.hnext + 0xf) & ~0xf
        self.hnext = p + max(16, n) + 32
        self.allocs.append((p, n))
        return p

    def _new(self, kind, content=b"", meta=None):
        h = self.hnext; self.hnext += 0x10
        self.handles[h] = [kind, bytearray(content), meta]
        return h
    new_handle = _new

    def _cstr(self, a):
        try:
            b = bytes(self.uc.mem_read(a, 96))
        except UcError:
            return None
        e = b.find(NUL)
        if 0 < e <= 80 and all(32 <= c < 127 for c in b[:e]):
            return b[:e].decode("latin1")
        return None

    # ---- the trap -------------------------------------------------------
    def _hook(self, uc, addr, size, ud):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        if addr in self.crt:
            ret = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
            uc.reg_write(UC_X86_REG_RSP, rsp + 8)
            n = self.abi.arg(uc, rsp, 1) & 0xffffffff
            nm = self.crt[addr]
            if nm == "malloc":
                uc.reg_write(UC_X86_REG_RAX, self._malloc(n))
            elif nm == "calloc":
                m = max(16, n * (self.abi.arg(uc, rsp, 2) & 0xffffffff))
                p = self._malloc(m); uc.mem_write(p, b"\0" * m)
                uc.reg_write(UC_X86_REG_RAX, p)
            else:
                uc.reg_write(UC_X86_REG_RAX, 0)
            uc.reg_write(UC_X86_REG_RIP, ret)
            return
        if self.JVMSTUB <= addr < self.JVMSTUB + 0x1000:
            idx = (addr - self.JVMSTUB) // 8
            ret = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
            uc.reg_write(UC_X86_REG_RSP, rsp + 8)
            if idx in (JVM_GETENV, JVM_ATTACH):       # (vm, void** penv, ...)
                penv = self.abi.arg(uc, rsp, 2)
                try:
                    uc.mem_write(penv, struct.pack("<Q", self.ENV))
                except UcError:
                    pass
            uc.reg_write(UC_X86_REG_RAX, 0)
            uc.reg_write(UC_X86_REG_RIP, ret)
            return
        if not (self.STUB <= addr < self.STUB + 0x10000):
            return
        idx = (addr - self.STUB) // 8
        name = IDX2NAME.get(idx, "")
        ret = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        A = lambda i: self.abi.arg(uc, rsp, i)
        for a in (A(2), A(3)):                          # opportunistic cstrings
            s = self._cstr(a)
            if s and s not in self.cstrings:
                self.cstrings.append(s)
        rv = self.ENV + 0x30000

        if name in ("ExceptionCheck", "ExceptionOccurred"):
            rv = 0
        elif name == "RegisterNatives":
            self._capture_register(A(3), A(4) & 0xffffffff)
        elif name in ("GetStringLength", "GetStringUTFLength"):
            h = self.handles.get(A(2)); rv = len(h[1]) if h else 0
        elif name == "GetArrayLength":
            h = self.handles.get(A(2)); rv = len(h[1]) if h else 16
        elif name in ("GetStaticFieldID", "GetFieldID"):
            rv = self._new("fieldid", meta=self._cstr(A(3)))
        elif name in ("GetStaticMethodID", "GetMethodID"):
            rv = self._new("methodid", meta=(self._cstr(A(3)), self._cstr(A(4))))
        elif name == "GetStaticObjectField":
            fld = self.handles.get(A(3))
            content = self.statics.get(fld[2] if fld else None)
            if content is None and len(self.statics) == 1:
                content = next(iter(self.statics.values()))
            rv = self._new("chars", content or b"")
        elif name == "SetStaticObjectField":
            fld, val = self.handles.get(A(3)), A(4)
            if fld and val in self.handles:
                self.statics[fld[2]] = bytes(self.handles[val][1])
            rv = 0
        elif name in ("NewByteArray", "NewIntArray"):
            rv = self._new("bytes", b"\0" * max(1, A(2) & 0xffffffff))
        elif name == "NewCharArray":
            rv = self._new("chars", b"\0" * max(1, A(2) & 0xffffffff))
        elif name == "AllocObject":
            rv = self._new("obj")
        elif name in ("NewStringUTF", "NewString"):
            s = self._cstr(A(2))
            if s and s not in self.cstrings:
                self.cstrings.append(s)
            rv = self._new("str", (s or "").encode("latin1"))
        elif name in ("GetByteArrayRegion", "GetCharArrayRegion", "GetIntArrayRegion"):
            self._region_get(A(2), A(3) & 0xffffffff, A(4) & 0xffffffff, A(5), name); rv = 0
        elif name in ("SetByteArrayRegion", "SetCharArrayRegion", "SetIntArrayRegion"):
            self._region_set(A(2), A(3) & 0xffffffff, A(4) & 0xffffffff, A(5), name); rv = 0
        elif name in ("GetStringRegion", "GetStringUTFRegion"):
            self._string_region(A(2), A(3) & 0xffffffff, A(4) & 0xffffffff, A(5), name); rv = 0
        elif name in ("CallNonvirtualVoidMethod", "CallVoidMethod"):
            self._maybe_string_init(name, rsp); rv = 0

        uc.reg_write(UC_X86_REG_RAX, rv)
        uc.reg_write(UC_X86_REG_RIP, ret)

    def _capture_register(self, tbl, n):
        for m in range(min(n, 64)):
            base = tbl + m * 24
            try:
                np_, sp_, fp = struct.unpack("<QQQ", self.uc.mem_read(base, 24))
            except UcError:
                break
            self.methods.append((self._cstr(np_), self._cstr(sp_), fp))

    def _region_get(self, arr, start, ln, buf, name):
        h = self.handles.get(arr)
        src = h[1] if h else bytearray(start + ln)
        wide = "Char" in name
        out = bytearray()
        for i in range(ln):
            v = src[start + i] if start + i < len(src) else 0
            out += bytes([v, 0]) if wide else bytes([v])
        try:
            self.uc.mem_write(buf, bytes(out))
        except UcError:
            pass

    def _region_set(self, arr, start, ln, buf, name):
        wide = "Char" in name
        try:
            raw = bytes(self.uc.mem_read(buf, ln * (2 if wide else 1)))
        except UcError:
            return
        if arr not in self.handles:
            self.handles[arr] = ["chars" if wide else "bytes", bytearray(), None]
        ba = self.handles[arr][1]
        while len(ba) < start + ln:
            ba.append(0)
        for i in range(ln):
            ba[start + i] = raw[i * 2] if wide else raw[i]
        if arr in self.fill_order:
            self.fill_order.remove(arr)
        self.fill_order.append(arr)

    def _string_region(self, strh, start, ln, buf, name):
        h = self.handles.get(strh)
        src = h[1] if h else b""
        wide = name == "GetStringRegion"
        out = bytearray()
        for i in range(ln):
            v = src[start + i] if start + i < len(src) else 0
            out += bytes([v, 0]) if wide else bytes([v])
        try:
            self.uc.mem_write(buf, bytes(out))
        except UcError:
            pass

    def _maybe_string_init(self, name, rsp):
        A = lambda i: self.abi.arg(self.uc, rsp, i)
        if name == "CallNonvirtualVoidMethod":   # (env, obj, clazz, mID, arr, off, cnt..)
            obj, mid, ab = A(2), A(4), 5
        else:                                    # (env, obj, mID, arr, off, cnt..)
            obj, mid, ab = A(2), A(3), 4
        meta = self.handles.get(mid, [None, None, None])[2]
        if not (isinstance(meta, tuple) and meta[0] == "<init>"):
            return
        arr, off, cnt = A(ab), A(ab + 1) & 0xffffffff, A(ab + 2) & 0xffffffff
        h = self.handles.get(arr)
        if h and obj in self.handles:
            self.handles[obj][0] = "str"
            self.handles[obj][1] = bytearray(bytes(h[1])[off:off + cnt])

    def _unmapped(self, uc, acc, addr, size, val, ud):
        if self.verbose:
            print("  [unmapped %#x rip %#x]" % (addr, uc.reg_read(UC_X86_REG_RIP)))
        return False

    # ---- driver ---------------------------------------------------------
    def run(self, fn, jni_args=(), as_onload=False, count=40_000_000):
        uc = self.uc
        if as_onload:
            args = [self.JVM, 0]
        else:
            args = [self.ENV, self._new("class")] + list(jni_args)
        self.abi.set_args(uc, args)
        rsp = (uc.reg_read(UC_X86_REG_RSP) & ~0xf) - 0x800
        uc.mem_write(rsp, struct.pack("<Q", self.RET))
        uc.reg_write(UC_X86_REG_RSP, rsp)
        try:
            uc.emu_start(fn, self.RET, count=count)
        except UcError as e:
            if self.verbose:
                print("  [emu stop %s rip %#x]" % (e, uc.reg_read(UC_X86_REG_RIP)))
        return uc.reg_read(UC_X86_REG_RAX)

    def dump_strings(self):
        out = list(self.cstrings)
        seen = set(out)
        u16 = re.compile(b"(?:[ -~]" + re.escape(NUL) + b"){3,}")
        for begin, end, _ in self.uc.mem_regions():
            try:
                b = bytes(self.uc.mem_read(begin, end - begin + 1))
            except UcError:
                continue
            for m in u16.finditer(b):
                try:
                    s = m.group().decode("utf-16le")
                except UnicodeDecodeError:
                    continue
                if s not in seen and len(s) >= 3:
                    seen.add(s); out.append(s)
        return out


# ---- JNI export-name demangling -------------------------------------
def demangle(sym):
    body = sym[len("Java_"):]
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c == "_" and i + 1 < len(body):
            nxt = body[i + 1]
            rep = {"1": "_", "2": ";", "3": "["}.get(nxt)
            if rep:
                out.append(rep); i += 2; continue
            out.append("/"); i += 1; continue
        out.append(c); i += 1
    return "".join(out)


def discover(em, registrars):
    """Populate em.methods via the most reliable available route."""
    # 1) Java_* export symbols (native-obfuscator standard exports)
    jx = [(n, va) for n, va in em.fmt.exports.items() if n.startswith("Java_")]
    if jx:
        for n, va in sorted(jx, key=lambda x: x[1]):
            em.methods.append((demangle(n), None, va))
        return "Java_* exports"
    # 2) JNI_OnLoad emulation (registers via RegisterNatives)
    if "JNI_OnLoad" in em.fmt.exports:
        em.run(em.fmt.exports["JNI_OnLoad"], as_onload=True)
        if em.methods:
            return "JNI_OnLoad emulation"
    # 3) explicit registrar functions (j2cc regc dispatch)
    for r in registrars:
        em.run(r)
    return "registrar emulation" if em.methods else None


# ============================ CLI ====================================
def _registrars(a):
    regs = [int(x, 0) for x in (a.registrar or [])]
    if getattr(a, "binary_json", None):
        bj = json.load(open(a.binary_json))
        for e in bj.get("nativeRegistry", []):
            for fa in e.get("fnAddrs", []):
                regs.append(int(fa, 0))
    return regs


def c_recover(a):
    em = Emu(a.dll, verbose=a.verbose)
    src = discover(em, _registrars(a))
    if not em.methods:
        print("no methods found. native-obfuscator: should be automatic.\n"
              "j2cc: pass --registrar 0x<regc_fnAddr> or --binary-json binary.json "
              "(j2c-dumper inspect-binary).")
        return
    print(f"# {len(em.methods)} native method(s) via {src} [{em.fmt.abi.name}]")
    for nm, sig, fp in em.methods:
        print(f"  {fp:#011x}  {nm or '?':<24} {sig or ''}")


def c_strings(a):
    em = Emu(a.dll, statics=_parse_statics(a.static), verbose=a.verbose)
    em.run(int(a.fn, 0))
    for s in em.dump_strings():
        print("  " + repr(s))


def c_call(a):
    em = Emu(a.dll, statics=_parse_statics(a.static), verbose=a.verbose)
    args = []
    if a.arg_bytes is not None:
        args.append(em._new("bytes", a.arg_bytes.encode("utf-8")))
    if a.arg_str is not None:
        args.append(em._new("str", a.arg_str.encode("utf-8")))
    rax = em.run(int(a.fn, 0), tuple(args))
    res = em.handles.get(rax)
    if (res is None or len(res[1]) == 0) and em.fill_order:
        res = em.handles[em.fill_order[-1]]
    if res is None:
        print("(no result buffer captured; rax=%#x)" % rax); return
    data = bytes(res[1]).rstrip(NUL)
    print("result kind=%s len=%d" % (res[0], len(data)))
    print("  ascii : " + repr(data.decode("latin1")))


def _parse_statics(items):
    out = {}
    for it in items or []:
        k, _, v = it.partition("=")
        if v.startswith("@"):
            v = open(v[1:], encoding="latin1").read().strip()
        out[k] = v.encode("latin1")
    return out


def main():
    p = argparse.ArgumentParser(description="emulation-based j2cc/native-obfuscator recovery")
    p.add_argument("--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("recover", help="list native methods (auto-discovers entry points)")
    r.add_argument("dll")
    r.add_argument("--registrar", nargs="+", help="explicit regc fnAddr(s) for j2cc")
    r.add_argument("--binary-json", help="j2c-dumper binary.json (reads nativeRegistry.fnAddrs)")
    r.set_defaults(f=c_recover)
    s = sub.add_parser("strings", help="dump decrypted string constants of a function")
    s.add_argument("dll"); s.add_argument("--fn", required=True)
    s.add_argument("--static", nargs="*", help="field=value or field=@file")
    s.set_defaults(f=c_strings)
    c = sub.add_parser("call", help="oracle: invoke a native method as a function")
    c.add_argument("dll"); c.add_argument("--fn", required=True)
    c.add_argument("--arg-bytes", help="UTF-8 string passed as a byte[] arg")
    c.add_argument("--arg-str", help="string passed as a String arg")
    c.add_argument("--static", nargs="*", help="field=value or field=@file")
    c.set_defaults(f=c_call)
    a = p.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
