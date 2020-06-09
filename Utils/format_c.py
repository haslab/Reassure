#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2020, Miguel Quaresma

import sys, re
from mbedtls import hmac, cipher

USAGE = '''Usage: {} [options] <file>
Converts the contents of <file> in an hex string for C
Options:
    -h Help'''

def format(raw):
    ''' Format an hex string according to C char arrays
    '''
    c_var = '"{}" \\\n'

    proc = re.sub(r'([0-9a-f]{2})', r'\\x\1', raw)
    lines = re.findall(r'(.{2,56})', proc)
    proc = ''

    for line in lines[:-1]:
        proc = proc + c_var.format(line)
    proc += '"{}";'.format(lines[-1])

    return proc

def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == '-h':
            print(USAGE.format(sys.argv[0]))
        else:
          inp_f = sys.argv[1]
          hex_contents = open(inp_f, 'rb').read().hex()
          print(format(hex_contents))
    else:
        print(USAGE.format(sys.argv[0]))
    
if __name__ == "__main__":
    main()
