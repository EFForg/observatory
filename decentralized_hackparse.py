#!/usr/bin/env python
#
# authors = ['pde@eff.org', 'dan@eff.org']
#
#
# Like hackparse, but instead of recursively sucking in .results files from
# some directory, it reads DER-encoded cert files from the command line
import decentralized_hackparse_lib as hackparse
import openssl_dump as od
import sys
from subprocess import Popen, PIPE
MAGIC_ERROR= "unable to load certificate"
print od.MOZ_VERIFY_ARGS

def parseblob(cert, fingerprint):
    a = Popen(od.DER_ARGS, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    try: pcert, err = a.communicate(cert)
    except:     err = MAGIC_ERROR

    if err.startswith(MAGIC_ERROR):
        return

    text, fp = od.opensslParseOneCert(pcert)
    moz_verifications = od.verifyCertChain([text], od.MOZ_VERIFY_ARGS)
    ms_verifications = od.verifyCertChain([text], od.MS_VERIFY_ARGS)
    verifications = zip(moz_verifications, ms_verifications)
    hackparse.add_cert_to_db(fingerprint, verifications, [text], [fp])

def main():
    # process fp arg separately
    if "--fp" not in sys.argv:
        raise ValueError, "Need --fp arg!"
    fp = sys.argv[sys.argv.index("--fp")+1]
    args = hackparse.process_args()
    parseblob(sys.stdin.read(), fp)


if __name__ == "__main__":
  main()


