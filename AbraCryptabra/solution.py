from __future__ import annotations

from hashlib import md5
from typing import TYPE_CHECKING
from argparse import ArgumentParser

from pwn import *
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import bytes_to_long

import crypto_attacks.attacks.lcg.truncated_state_recovery
from crypto_attacks.attacks.lcg.truncated_parameter_recovery import attack

if TYPE_CHECKING:
    from argparse import Namespace

MAGICKA = 108314726549199134030277012155370097074
ARMOR = 31157724864730593494380966212158801467


def convert_binary_to_ascii(bin_str):
    print(f'Received binary string: {bin_str}')
    n = int(bin_str, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()


def verify_list(l):
    # if l[-1] != 0:
    #     return False

    non_zero_seen = False

    positive_success = True
    for entry in l[:-1]:
        if entry == 1:
            non_zero_seen = True
        if entry != 0 and entry != 1:
            positive_success = False
            break

    negative_success = True
    for entry in l[:-1]:
        if entry == -1:
            non_zero_seen = True
        if entry != 0 and entry != -1:
            negative_success = False
            break

    return (positive_success or negative_success) and non_zero_seen


def transform_list(l):
    list_sign = 1
    for i in l:
        if i != 0:
            list_sign = i
            break

    bin_str = ''.join([str(list_sign * val) for val in list(l[:-1])])
    return convert_binary_to_ascii(bin_str)


def merkle_hellman_attack(ciphertext, public_key):
    nbits = len(public_key)
    N = ceil(sqrt(nbits) / 2)
    M = Matrix(ZZ, nbits + 1, nbits + 1)

    for i in range(nbits):
        M[i, i] = 1
        M[i, nbits] = N * public_key[i]

    M[nbits, nbits] = N * -ciphertext

    M_prime = M.LLL(algorithm='NTL:LLL', use_givens=True)  # (delta=.99, eta=.51, verbose=True)
    for row in list(M_prime):
        if verify_list(row):
            return transform_list(row)

    for col in list(M_prime.T):
        if verify_list(col):
            return transform_list(col)

    M_prime = M.LLL(algorithm='NTL:LLL', use_givens=False)
    for row in list(M_prime):
        if verify_list(row):
            return transform_list(row)

    for col in list(M_prime.T):
        if verify_list(col):
            return transform_list(col)

    M_prime = M.LLL()
    for row in list(M_prime):
        if verify_list(row):
            return transform_list(row)

    for col in list(M_prime.T):
        if verify_list(col):
            return transform_list(col)

    # M_prime = M.BKZ(algorithm='NTL', use_givens=True, block_size=50)
    # for row in list(M_prime):
    #     if verify_list(row):
    #         return transform_list(row)
    #
    # for col in list(M_prime.T):
    #     if verify_list(col):
    #         return transform_list(col)

    M_prime = M.BKZ(algorithm='NTL', use_givens=False, block_size=50)
    for row in list(M_prime):
        if verify_list(row):
            return transform_list(row)

    for col in list(M_prime.T):
        if verify_list(col):
            return transform_list(col)

    M_prime = M.BKZ(proof=True, block_size=50)
    for row in list(M_prime):
        if verify_list(row):
            return transform_list(row)

    for col in list(M_prime.T):
        if verify_list(col):
            return transform_list(col)

    M_prime = M.BKZ(proof=False, block_size=50)
    for row in list(M_prime):
        if verify_list(row):
            return transform_list(row)

    for col in list(M_prime.T):
        if verify_list(col):
            return transform_list(col)

    return None


def main(hst: str, prt: int):
    conn: remote = remote(hst, prt)
    msg = conn.recv().decode()
    while '>' not in msg:
        print(msg, end='')
        msg = conn.recv().decode()
    print(msg, end='')

    my_health = 100
    server_health = 200

    # Get 33 values from the lcg, might not be enough
    y = []
    for _ in range(my_health // 3):
        conn.sendline('0'.encode())
        recv_line = conn.recvline().decode().rstrip()
        my_health -= 1
        print(f'0{recv_line:70s}My Health: {my_health:<6d}Server Health: {server_health}')
        recv_line = conn.recvline().decode().rstrip()
        print(f'{recv_line}\n > ', end='')
        conn.recv()  # Grab the rest but throw it away, not needed
        y.append(int(recv_line))

    print('\b\b\b\b\nY values:', end='')
    print(y, end='\n\n')

    # Use the imported library to generate a c and x_0 value
    tlcg_params = attack(y=y, k=127, s=32, m=MAGICKA, a=ARMOR)

    m, a, c, x_0 = next(tlcg_params)
    print(f'Generated values\nc: {c}\nx_0:{x_0}')
    while m != MAGICKA and a != ARMOR:
        print('Bad choice of m and a. Re-choosing...')
        print(f'Generated values\nc: {c}\nx_0:{x_0}')
        m, a, c, x_0 = next(tlcg_params)

    print('\nRecovering state...')
    x = crypto_attacks.attacks.lcg.truncated_state_recovery.attack(y=y, k=127, s=32, m=MAGICKA, a=ARMOR, c=c)
    print('Recovered values:')
    print(x, end='\n\n')

    x_next = (ARMOR * x[-1] + c) % MAGICKA
    y_next = x_next >> 95
    while True:
        conn.sendline(str(y_next).encode())
        recv_line = conn.recvline().decode().rstrip()
        print(f' > {str(y_next) + recv_line:70s}', end='')
        if 'easy' in recv_line:
            my_health -= 1
            print(f'My Health: {my_health:<6d}Server Health: {server_health}')
            recv_line = conn.recvline().decode()
            print(f'{recv_line}', end='')
            y.append(int(recv_line))

            if my_health == 0:
                print(conn.recvall().decode())
                exit()
        else:
            server_health -= 1
            print(f'My Health: {my_health:<6d}Server Health: {server_health}')
            y.append(y_next)

            # Short circuit now before continuing
            if server_health == 0:
                break

        conn.recv()  # Grab the rest but throw it away, not needed

        x_next = (ARMOR * x_next + c) % MAGICKA
        y_next = x_next >> 95

    # We are in a winning state at this point woohoo! First recv_line is trash, throw it out
    conn.recvline()
    recv_line = conn.recvline().decode().strip().rstrip()
    print(f'\nScroll of worthiness lines: {recv_line}')

    scroll = []
    for _ in range(int(recv_line)):
        recv_line = conn.recvline().decode().rstrip()
        print(recv_line)
        scroll.append(recv_line)
    scroll = [int(x) for x in scroll]

    ciphertext = conn.recvline().decode().rstrip()
    print(f'\nEncrypted Flag: {ciphertext}\n')
    conn.close()

    for _ in range(my_health):
        x_next = (ARMOR * x_next + c) % MAGICKA

    encryption_key = md5(str(x_next >> 95).encode()).digest()
    print(f'\nMD5 Hash: {encryption_key}')
    aes = AES.new(encryption_key, AES.MODE_CBC)
    plaintext = aes.decrypt(bytes.fromhex(ciphertext))
    print(f'Recovered plaintext: {plaintext}')
    clean_value = unpad(plaintext[plaintext.index(b'Harry'):], AES.block_size)
    disrupted_flag = clean_value.split(b' ')[-1]
    print(f'Isolated flag: {disrupted_flag}')
    flag_long = bytes_to_long(bytes.fromhex(disrupted_flag.decode()))
    print(f'Long value recovered: {flag_long}')

    res = merkle_hellman_attack(flag_long, scroll)
    if res is None:
        print('Could not find a solution :(')
        return False
    else:
        print(f'Flag Get! HTB{{{res}}}')
        return True


if __name__ == '__main__':
    parser: ArgumentParser = ArgumentParser()
    parser.add_argument('host_port', type=str,
                        help='The host and port in host:port format (as given by Hack The Box)')
    args: Namespace = parser.parse_args()
    host, port = args.host_port.split(':')
    result = main(host, int(port))
    attempts = 0
    while not result:
        print('\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ RESTARTING ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n')
        try:
            result = main(host, int(port))
        except Exception:
            continue
        if attempts == 33:
            print('max attempts reached')
            exit()
        attempts += 1
    print(f'Attempts {attempts}')
