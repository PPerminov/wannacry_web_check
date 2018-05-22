import socket
import struct
from impacket import smb


def scan(host):
    timeout = 2
    try:
        s = socket.create_connection((host, 445), timeout=timeout)
        if s is None:
            return 1

        cs = smb.SMB('*SMBSERVER', host, sess_port=445, timeout=timeout)
        uid = cs.login('', '')
        tid = cs.tree_connect_andx(r'\\\\IPC$', '')
        base_probe = (
            '\x00\x00\x00\x4a\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x01\x28'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + struct.pack('<H', tid) + '\xb9\x1b' +
            struct.pack('<H', cs._uid) +
            '\xb1\xb6\x10\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x4a\x00\x02'
            '\x00\x23\x00\x00\x00\x07\x00\x5c\x50\x49\x50\x45\x5c\x00'
        )

        doublepulsar_probe = (
            '\x00\x00\x00\x4f\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x18\x07\xc0'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + struct.pack('<H', tid) + '\x4a\x3d' +
            struct.pack('<H', cs._uid) +
            '\x41\x00\x0f\x0c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            '\x00\xa6\xd9\xa4\x00\x00\x00\x0c\x00\x42\x00\x00\x00\x4e\x00\x01'
            '\x00\x0e\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x00\x00\x00'
        )
        cs._sess._sock.send(base_probe)
        res = cs._sess._sock.recv(1024)
        status = struct.unpack('<L', res[9:13])[0]
        if status == 0xc0000205:
            double_infection = False
            try:
                cs._sess._sock.send(doublepulsar_probe)
                res = cs._sess._sock.recv(1024)
                code = struct.unpack('<L', res[34:38])[0]
                sig1 = struct.unpack('<L', res[18:22])[0]
                sig2 = struct.unpack('<L', res[22:26])[0]
                if code == 0x51:
                    double_infection = True
            except:
                pass
            if double_infection:
                return 3
            else:
                return 4
        elif status == 0xc0000008 or status == 0xc0000022:
            return 5
        else:
            return 6
    except:
        return 12
