#!/usr/bin/env python

# This script builds up transvalidity from the bottom up by creating
# an expanded trust root of CA certs that are actually trusted
# It MUST be run from the observatory git repo's root directory: observatory.
# This is of course a horrible hack, just for now, etc etc

import sys, os, subprocess, base64
import openssl_dump
import dbconnect
import _mysql_exceptions

# these are also hardcoded below. yuck, coding fast
INITIAL_TRUST_PATH = './allcerts/'
FULL_CA_TRUST_PATH = './allvalidcacerts/'
FULL_CA_TRUST_ARGS = ['openssl', 'verify', '-CApath', FULL_CA_TRUST_PATH]

class TransvalidityChecker(object):
    def __init__(self):
        self.gdb, self.gdbc = dbconnect.dbconnect()

    def expandTrustRootToValidCAs(self):
        num_added = 0
        # get CA certs
        ca_certs = self.getCertsFromWhereClause("`X509v3 extensions: basicConstraints` LIKE '%CA:TRUE%' and (Valid IS NULL or Valid != 1)")
        print "Found %s ostensibly non-trusted CA certs" % len(ca_certs)
        for fp_hex, cert in ca_certs:
            # is this cert valid, given existing trust root?
            if self.verifyAgainstTrustRoot(fp_hex, cert):
                self.addCertToTrustRoot(fp_hex, cert)
                num_added += 1
        return num_added

    def generateTrustRoot(self):
        while True: 
            num = self.expandTrustRootToValidCAs()
            if num == 0:
                break
            print "Added %s new CA certs to root" % num
    
    def verifyAgainstTrustRoot(self, fp_hex, cert):
        # hack, must be in the right directory. todo fix this
        filename = '/tmp/%s.crt' % fp_hex
        f = open(filename, 'w')
        f.write(cert)
        f.close()
        self.convertToPem(filename)
        f = open(filename, 'r')
        cert = f.read()
        f.close()
        try:
            os.remove(filename)
        except:
            print "Couldnt remove file"
        if openssl_dump.verifyOneCert(cert, [], FULL_CA_TRUST_ARGS, []).startswith("Yes"):
            return True
        else: return False

    def addCertToTrustRoot(self, fp_hex, cert):
        # hack, must be in the right directory. todo fix this
        filename = 'allvalidcacerts/%s.crt' % fp_hex
        f = open(filename, 'w')
        f.write(cert)
        f.close()
        self.convertToPem(filename)
        self.rehash()
        # also mark it valid in the db
        q = "UPDATE parsed_certs set Valid=1 where cert_fp = unhex('%s')" % fp_hex
        self.executeQuery(q)

    def rehash():
        subprocess.call(['c_rehash', 'allvalidcacerts'])

    def getCertsFromWhereClause(self, clause):
        q = "SELECT hex(cert_fp), raw_cert FROM certs JOIN parsed_certs USING (cert_fp) WHERE %s" % clause
        self.executeQuery(q)
        return self.gdbc.fetchall()

    def executeQuery(self, q):
        print "Executing: %s" % q
        try:
            self.gdbc.execute(q)
        except _mysql_exceptions.OperationalError, e:
            # if two instances of this to run at once 
            if "Duplicate column name" in `e`:
                # Another instance already created this column
                return
            raise e

    def convertToPem(self, filename):
        subprocess.call(['openssl', 'x509', '-in', filename, '-inform', 'der', '-outform', 'pem', '-out', filename])



if __name__ == '__main__':
    b = TransvalidityChecker()
    b.generateTrustRoot()
