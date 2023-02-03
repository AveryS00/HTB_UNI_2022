from __future__ import annotations

from typing import TYPE_CHECKING
from argparse import ArgumentParser

from pwn import *

if TYPE_CHECKING:
    from argparse import Namespace

PREPEND: str = 'Property: '


def xor(a: bytes, b: bytes) -> bytes:
    return bytes([aa ^ bb for aa, bb in zip(a, b)])


def main(hst: str, prt: int):
    conn: remote = remote(hst, prt)
    print(conn.recv())

    # start by padding to a single block with a's
    initial_padding: bytes = 'aaaaaa'.encode()
    print(f'Sending {initial_padding.hex().encode()}')
    conn.sendline(initial_padding.hex().encode())
    print(f'Sent')

    # Get the output tag
    output: str = conn.recv().decode()
    output_tag: str = output.split('\n')[0].rstrip()
    print(f'Received tag {output_tag}')
    c_0: bytes = bytes.fromhex(output_tag)
    print(f'c_0: {c_0.hex()}')

    # Construct a new message as c_0 ^ p_0 to make it so that the plaintext becomes 0
    p_0: bytes = PREPEND.encode() + initial_padding
    print(f'p_0: {p_0.hex()}')
    p_1: bytes = xor(p_0, c_0)
    print(f'p_1: {p_1.hex()}')
    new_send: bytes = initial_padding + p_1
    print(f'Prepared new message {new_send}. Sending...')
    conn.sendline(new_send.hex().encode())

    # Get this result is now c_0 ^ c_1, so extract c_1
    new_output: str = conn.recv().decode()
    new_output_tag: str = new_output.split('\n')[0].rstrip()
    print(f'Received tag {new_output_tag}')
    c_1: bytes = xor(bytes.fromhex(new_output_tag), c_0)
    print(f'c_1: {c_1.hex()}')

    # Now make a new message that is c_1 ^ p_1
    p_2: bytes = xor(c_1, p_1)
    new_new_send: bytes = initial_padding + p_1 + p_2
    print(f'Prepared new message {new_new_send}. Sending...')
    conn.sendline(new_new_send.hex().encode())
    print(conn.recvall())
    conn.close()


if __name__ == '__main__':
    parser: ArgumentParser = ArgumentParser()
    parser.add_argument('host_port', type=str,
                        help='The host and port in host:port format (as given by Hack The Box)')
    args: Namespace = parser.parse_args()
    host, port = args.host_port.split(':')
    main(host, int(port))
