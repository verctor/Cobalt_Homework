import socket
import struct
import base64
import hashlib
import time

import define

from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto import Cipher
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC


iv = 'abcdefghijklmnop'
sk = '1234567890abcdef'

empty = '\x00'

def sha256(s):
    sha = hashlib.sha256()
    sha.update(s)
    return sha.digest()

session_key = sha256(sk)[:16]
hash_key = sha256(sk)[16:]

def p16(i):
    return struct.pack('<H', i)

def p32_b(i):
    return struct.pack('>I', i)

def b32_b(p):
    return struct.unpack('>I', p)[0]

def metadata():
    md = sk                              # session key
    md += p16(936)                       # ansi code page
    md += p16(936)                       # oem code page
    md += '23333\t'                       # beacon id
    md += '6666\t'                       # pid
    md += '6.1\t'                       # version
    md += '233.233.233.233\t'            # internal address
    md += 'FakeComp\t'                   # computer name
    md += 'FakeUserButAdmin *\t'         # username
    md += '1\t'                          # os is x64 system
    md += '1\t'                          # beacon is x64 process

    return md

def aes_enc(plain, k, iv):
    aes = Cipher.AES.new(k, Cipher.AES.MODE_CBC, iv)
    return aes.encrypt(plain)

def aes_dec(ct, k, iv):
    aes = Cipher.AES.new(k, Cipher.AES.MODE_CBC, iv)
    return aes.decrypt(ct)

def bs_encrypt(plain):
    p = p32_b(int(time.time()))
    p += p32_b(len(plain))
    p += plain

    if len(p) % 16 != 0:
        p += 'a' * (16 - (len(p) % 16))

    ct = aes_enc(p, session_key, iv)
    return ct + HMAC.new(hash_key, ct, digestmod=SHA256).digest()[:16]

def bs_decrypt(ct):
    ct = ct[:-16]  # ignore hmac
    dec = aes_dec(ct, session_key, iv)

    timestamp = b32_b(dec[:4])
    data_len = b32_b(dec[4:8])
    return timestamp, dec[8: 8 + data_len]

def fake_rsa_pkcs1(rsa, plain):
    if len(plain) > 117:
        raise Exception('too big')

    pad_len = 117 - len(plain)
    p = '\x00\x02' + 'a' * 8 + 'a' * pad_len + '\x00' + plain
    return rsa.encrypt(p, 1)[0]

def recv_frame(sock):
    try:
        chunk = sock.recv(4)
    except:
        return("")
    if len(chunk) < 4:
        return()
    slen = struct.unpack('<I', chunk)[0]
    chunk = sock.recv(slen)
    while len(chunk) < slen:
        chunk = chunk + sock.recv(slen - len(chunk))
    return(chunk)

def send_frame(sock, chunk):
    slen = struct.pack('<I', len(chunk))
    sock.sendall( slen + chunk )

def getStage(sock):
    send_frame(sock,"arch=x86")
    send_frame(sock,"pipename=foobar")
    send_frame(sock,"block=1000")
    send_frame(sock,"go")
    stager = recv_frame(sock)
    return stager

def connect_and_stage():
    s = socket.create_connection(('127.0.0.1', 2222))
    stg = getStage(s)
    print("Got Stage " + str(len(stg)))
    return s, stg

def dumpPublicKey():
    s, stg = connect_and_stage()

    sig = '\x00\x07\x00\x03\x01\x00'
    sig_obf = ''
    for i in list(sig):
        sig_obf += chr(ord(i) ^ 0x69)

    idx = stg.index(sig_obf)
    pubkey_obf = stg[idx + len(sig): idx + len(sig) + 256]
    pubkey = ''.join(map(lambda x : chr(ord(x) ^ 0x69), pubkey_obf))

    pub_b64 = base64.b64encode(pubkey[:162])
    final = '-----BEGIN PUBLIC KEY-----\n' + pub_b64 + '\n-----END PUBLIC KEY-----'

    open('public.der', 'wb').write(final)
    return s, pubkey[:162]

def test_metadata():
    s, pubkey = dumpPublicKey()
    rsa = RSA.importKey(pubkey)

    md = p32_b(0xbeef) + p32_b(len(metadata())) + metadata()

    first_md = 'aaaa' + fake_rsa_pkcs1(rsa, md)
    send_frame(s, first_md)

    return s

def parse_tasks(tasks):
    task_list = []
    ptr = 0
    while ptr < len(tasks):
        tmp = b32_b(tasks[ptr: ptr + 4])
        try:
            command = define.command_rev[tmp]
        except KeyError:
            print('UNKNOW COMMAND: {}, should be add to define.py'.format(tmp))
            command = "UNKNOWN COMMAND"

        ptr += 4

        tmp = b32_b(tasks[ptr: ptr + 4])
        ptr += 4

        task = tasks[ptr: ptr + tmp]
        ptr += tmp

        task_list.append((command, task))

    return task_list
    

if __name__ == '__main__':
    s = test_metadata()
    while True:
        tasks_enc = recv_frame(s)
        if len(tasks_enc) == 1:
            #print('got empty task')
            pass
        else:
            t, tasks = bs_decrypt(tasks_enc)
            print('-------------- tasks ------------\n')
            print('time: ' + datetime.fromtimestamp(t).ctime())
            tasks_list = parse_tasks(tasks)

            for i in tasks_list:
                print('recv task: ' + i[0])
                print('task string: ' + (repr(i[1]) if len(i[1]) < 0x100 else repr(i[1][:0x50]) + '......'))
                print('\n------------------------\n')
            
            print('------------ tasks end ------------\n')

        send_frame(s, empty)
