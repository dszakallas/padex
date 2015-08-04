#!/usr/bin/env python3

'''
Padding oracle exploit challenge.
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

from Crypto.Cipher import AES
from flask import Flask, request, abort, render_template
from base64 import b64decode, b64encode
import argparse, sys

description = 'Padding oracle exploit exercise.'
create = 'Create the encrypted message with the flag in base64 format'
run = 'Run the vulnerable oracle'

usage = '''padex <command> [<args>]

Commands are:
   create     ''' + create + '''
   run        ''' + run + '''
'''


def pad16(a):
    """Pad to a multiple of 16. Padding length will range from 1 to 16"""
    size = 16 - (a.__len__() % 16)
    return a + bytearray([size for _ in range(0, size)])


# Globals for the oracle
oracle = Flask(__name__.split('.')[0] + "_oracle")
key = iv = ''


@oracle.route('/', methods=['GET'])
def info():
    return render_template("index.html")


@oracle.route('/', methods=['POST'])
def decrypt():
    if request.content_length != 44:
        abort(400)

    data = b64decode(request.get_data())
    aes = AES.new(key, AES.MODE_CBC, IV=iv)
    mess = aes.decrypt(data)
    padsize = mess[-1]

    if padsize < 1 or padsize > 16:
        abort(403)

    for x in mess[-padsize:-1]:
        if x != padsize:
            abort(403)

    return 'OK', 200


def run():
    parser = argparse.ArgumentParser(description=create)
    parser.add_argument('key32',    type=str,   action='store', help="key for 256 bit AES in base64 format")
    parser.add_argument('iv16',     type=str,   action='store', help="16 byte initialization vector in base64 format")
    parser.add_argument('--host',   type=str,   action='store', help="hostname of the web server", default="127.0.0.1")
    parser.add_argument('--port',   type=int,   action='store', help="port of the web server", default="12345")

    args = parser.parse_args(sys.argv[2:])

    global key, iv, message
    key = b64decode(args.key32)
    iv = b64decode(args.iv16)

    oracle.run(host=args.host, port=args.port)


def create():
    parser = argparse.ArgumentParser(description=create)
    parser.add_argument('key32',    type=str,   action='store', help="key for 256 bit AES in base64 format")
    parser.add_argument('iv16',     type=str,   action='store', help="16 byte initialization vector in base64 format")
    parser.add_argument('flag',   type=str,   action='store', help='flag string for the user')

    args = parser.parse_args(sys.argv[2:])

    key = b64decode(args.key32)
    iv = b64decode(args.iv16)
    flag = bytearray(args.flag, 'utf-8')

    padded = pad16(b"Congrats, your flag is '" + flag + b"'")

    aes = AES.new(key, AES.MODE_CBC, IV=iv)

    print(b64encode(aes.encrypt(padded)).decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(
        description=description,
        usage=usage)
    parser.add_argument('command', help='Command to run')
    args = parser.parse_args(sys.argv[1:2])

    if args.command == 'create':
        create()
    elif args.command == 'run':
        run()
    else:
        print('Unrecognized command')
        parser.print_help()
        exit(1)


if __name__ == '__main__':
    main()


