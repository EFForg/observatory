import sys, os, subprocess
import openssl_dump

def readPemChainFromFile(fileObj):
    final = []
    substrate = ""
    start = False
    while 1:
        certLine = fileObj.readline()
        if not certLine:
            break
        if not start:
            if certLine == '-----BEGIN CERTIFICATE-----\n':
                start = True
            else:
                continue
        substrate += certLine
        if certLine.startswith('-----END CERTIFICATE--'):
            final.append(substrate)
            substrate = ""
    return final

def checkChain(chain):
    # todo think about timestamp -attime issue
    verify_all = openssl_dump.verifyOneCert(chain[-1], chain[0:-1], openssl_dump.ALL_VERIFY_ARGS, [], 3, True)
    verify_moz = openssl_dump.verifyOneCert(chain[-1], chain[0:-1], openssl_dump.MOZ_VERIFY_ARGS, [], 3, True)
    verify_ms = openssl_dump.verifyOneCert(chain[-1], chain[0:-1], openssl_dump.MS_VERIFY_ARGS, [], 3 True)
    print verify_all, verify_moz, verify_ms

# Read ASN.1/PEM X.509 certificates on stdin, parse each into plain text,
# then build substrate from it
if __name__ == '__main__':
    chain = readPemChainFromFile(sys.stdin)
    if not chain:
        print "No chain to check!"
    else:
        checkChain(chain)

