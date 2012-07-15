#!/usr/bin/env python

import sys, os, subprocess, base64
import openssl_dump
import dbconnect

# ugly hack
TRANSVALID_PATH = './allvalidcacerts'
TRANSVALID_VERIFY_ARGS = ['openssl', 'verify', '-CApath', TRANSVALID_PATH]

def readPemChainFromFile(fileObj):
    final = []
    substrate = ""
    start = False
    while 1:
        certLine = fileObj.readline()
        if not certLine:
            break
        if not start:
            if certLine.startswith('-----BEGIN CERTIFICATE--'):
                start = True
            else:
                continue
        if len(certLine) > 65:
            j = 0
            newcertline = ""
            while (j*64 < len(certLine)):
                newcertline += certLine[j*64:(j+1)*64] + "\n"
                j += 1
            certLine = newcertline.replace('\n\n', '\n')
        substrate += certLine
        if certLine.startswith('-----END CERTIFICATE--'):
            final.append(substrate)
            substrate = ""
    return final

def checkChain(chain):
    verify_moz = openssl_dump.verifyOneCert(chain[0], chain[1:], openssl_dump.MOZ_VERIFY_ARGS, [])
    verify_ms = openssl_dump.verifyOneCert(chain[0], chain[1:], openssl_dump.MS_VERIFY_ARGS, [])
    verify_transvalid = openssl_dump.verifyOneCert(chain[0], chain[1:],TRANSVALID_VERIFY_ARGS, [])
    # oh boy using stdout to communicate with php is ugly...
    print verify_moz
    print verify_ms
    print verify_transvalid

# Read ASN.1/PEM X.509 certificates on stdin, parse each into plain text,
# then build substrate from it
if __name__ == '__main__':
    chain = readPemChainFromFile(sys.stdin)
    if not chain:
        sys.stderr.write("No chain to check!\n")
    else:
        checkChain(chain)

