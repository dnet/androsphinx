#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
# SPDX-License-Identifier: MIT

from argparse import ArgumentParser
from socket import create_connection
from subprocess import Popen, PIPE
from os import path
from uuid import uuid4
from itertools import product
from sys import stderr


def main():
    parser = ArgumentParser(
            description='Tests conformity of Androsphinx and pwdsphinx to each other')
    parser.add_argument('path', metavar='/path/to/pwdsphinx',
            help='pwdsphinx path')
    parser.add_argument('--host', dest='host', default='localhost',
            help='Androsphinx REPL host')
    parser.add_argument('--port', dest='port', type=int, default=23555,
            help='Androsphinx REPL port')
    args = parser.parse_args()
    Tester(args.path, (args.host, args.port)).run()


class Tester(object):
    def __init__(self, ps_path, addr):
        self.asrepl = create_connection(addr).makefile('rw')
        self.path = ps_path

    def asrepl_cmd(self, *args):
        print(' '.join(map(str, args)), file=self.asrepl, flush=True)
        return self.asrepl.readline().replace('ASREPL> ', '').strip('\n')

    def pwdsphinx_cmd(self, master_pwd, *args):
        cmdline = ['python3', '-m', 'pwdsphinx.sphinx']
        cmdline.extend(map(str, args))
        ps = Popen(cmdline, cwd=self.path, stdin=PIPE, stdout=PIPE)
        stdout, _stderr = ps.communicate(
                master_pwd.encode('utf-8') if master_pwd else None)
        if ps.returncode != 0:
            raise RuntimeError(f"pwdsphinx error, returncode was {ps.returncode}")
        return stdout.rstrip(b'\n').decode('utf-8')

    def run(self):
        master_pwd = "conformanceTestingMasterPw"
        hostname = f"{uuid4()}.example.tld"
        for size in range(2, 20):
            for s in product('u.', 's.', 'l.', 'd.'):
                chars = ''.join(s).replace('.', '')
                if not chars:
                    continue
                print(f'\r{size:2}/{chars:4}', end='', file=stderr)

                username = f"user-{uuid4()}"
                ps_pw = self.pwdsphinx_cmd(master_pwd, "create", username, hostname, chars.replace('s', ''), size, '!$(' if 's' in chars else '')
                as_pw = self.asrepl_cmd("get", master_pwd, username, hostname)
                assert ps_pw == as_pw, f"{size} of {chars!r} -> {ps_pw!r} != {as_pw!r}"

                username = f"user-{uuid4()}"
                as_pw = self.asrepl_cmd("create", master_pwd, username, hostname, chars, size)
                ps_ls = self.pwdsphinx_cmd(None, "list", hostname)
                assert username in ps_ls, f"{ps_ls!r} does not contain {username!r}"
                ps_pw = self.pwdsphinx_cmd(master_pwd, "get", username, hostname)
                assert ps_pw == as_pw, f"{size} of {chars!r} <- {ps_pw!r} != {as_pw!r}"

                as_pw = self.asrepl_cmd("change", master_pwd, username, hostname, chars, size)
                self.pwdsphinx_cmd(master_pwd, "commit", username, hostname)
                ps_pw = self.pwdsphinx_cmd(master_pwd, "get", username, hostname)
                assert ps_pw == as_pw, f"{size} of {chars!r} <= {ps_pw!r} != {as_pw!r}"
        print(file=stderr)


if __name__ == '__main__':
    main()
