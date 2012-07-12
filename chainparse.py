#!/usr/bin/env python

# get transvalidity working

import sys, os, subprocess, base64
import openssl_dump

INITIAL_TRUST_PATH = './allcerts/'
FULL_CA_TRUST_PATH = './allvalidcacerts/'
FULL_CA_TRUST_ARGS = ['openssl', 'verify', '-CApath', FULL_CA_TRUST_PATH]


class TransvalidityChecker(object):
    def __init__(self, cert):
        # the main cert to check
        self.cert = cert
        self._bad_fp_dict

    def expandTrustRootToValidCAs(self):
        num_added = 0
        # get CA certs
        ca_certs = self.getCertsFromWhereClause("`X509v3 extensions: basicConstraints` LIKE '%CA:TRUE% and Valid != 1")
        for cert in ca_certs:
            # is this cert valid, given existing trust root?
            if self.verifyAgainstTrustRoot(cert):
                self.addCertToTrustRoot(cert)
                num_added += 1
        return num_added

    def generateTrustRoot(self):
        while True: 
            num = self.expandTrustRootToValidCAs()
            if num == 0:
                break
            print "Added %s new CA certs to root" % num
    
    def verifyAgainstTrustRoot(self, cert):
        if openssl_dump.verifyOneCert(cert, [], [], 3, True) == "Yes":
            return True
        else: return False

    def addCertToTrustRoot(self, cert):
        f = open('allvalidcacerts/%s' % self.getName(cert), 'w')
        f.write(cert)
        f.close()
    
    def getName(self, cert):
        # TODO PEM->DER
        q = "SELECT unhex(cert_fp) FROM certs WHERE cert = %s"

    def getCertsFromWhereClause(self, clause):
        q = "SELECT unhex(cert_fp), raw_cert FROM certs JOIN parsed_certs USING cert_fp WHERE %s" % clause
        res = self.executeQuery(q)




    def expandValidCerts(self):
        valid_certs = self.getCertsFromWhereClause("Valid = 1")
        subjects = self.getFieldFromCerts("Subject")
        subjects = self.filterSelfSigned()

        valid_certs = self.getValidCerts()
        subjects = self.getSubjects(valid_certs)
        # Get certs whose issuer is in this set of subjects
        certs = self.getIssuers(subjects)
        
        
        

    def inTrustRoot(self, cert):
        # perhaps this is unnecessary computation
        verify = openssl_dump.verifyOneCert(cert, [], openssl_dump.ALL_VERIFY_ARGS, [], 3, True)
        if verify == "Yes":
            return True
        else:
            return False

    def getFp(self, cert):
        raise ValueError, "error not implemented"

    def addCertFpToBadList(cert):
        fp = self.getFp(cert)
        self._bad_fp_dict[fp] = 1

    def certFpInBadList(self, cert):
        fp = self.getFp(cert)
        if fp in self._bad_fp_dict:
            return True
        return False

    def getDistinctIssuingCerts(self, cert):
        # First get issuer for this certificate, assume not self-signed
        q = "SELECT issuer FROM certs WHERE cert_fp = %s" % self.getFp(cert)
        # TODO get result
        q = "SELECT raw_cert FROM certs a JOIN parsed_certs b USING(cert_fp) WHERE "

    def testTransvalidity(self, certlist):
        # if anything in the list is transvalid we return true
        # to make recursion work
        for cert in certlist:
            if self.certFpInBadList(cert):
                return False
            if self.isValid(cert):
                return True
            issuers = filter(lambda x: not self.certFpInBadList(x), self.getDistinctIssuingCerts(cert))
            if not issuers:
                self.addCertFpToBadList(cert)
                return False
            else:
                return self.testTransvalidity(issuers)


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
    # todo think about timestamp -attime issue
    #print "Chain is %s" % str(chain)
    #print "END ENTITY CERT IS:"
    #print chain[0]
    #print "LAST CERT IS:"
    #print chain[-1]
    #verify_all = openssl_dump.verifyOneCert(chain[0], chain[1:], openssl_dump.ALL_VERIFY_ARGS, [])
    verify_moz = openssl_dump.verifyOneCert(chain[0], chain[1:], openssl_dump.MOZ_VERIFY_ARGS, [])
    verify_ms = openssl_dump.verifyOneCert(chain[0], chain[1:], openssl_dump.MS_VERIFY_ARGS, [], 3)
    print verify_moz
    print verify_ms

# Read ASN.1/PEM X.509 certificates on stdin, parse each into plain text,
# then build substrate from it
if __name__ == '__main__':
    chain = readPemChainFromFile(sys.stdin)
    if not chain:
        print "No chain to check!"
    else:
        checkChain(chain)

