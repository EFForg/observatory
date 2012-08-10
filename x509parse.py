#!/usr/bin/env python

from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
from M2Crypto import X509
from datetime import datetime
import crypto
import crypto_utils
import dbconnect
import MySQLdb
import _mysql_exceptions


X509V3_EXT_ERROR_UNKNOWN = (1L << 16)
TABLE_NAME = 'parsed_certs'

VERSION_DICT = {2: "v3",
                1: "v2",
                0: "v1"}

def readFromObservatory(fileObj):
    substrate = "-----BEGIN CERTIFICATE-----\n";
    while 1:
        certLine = fileObj.readline()
        if not certLine:
            break
        if len(certLine) > 65:
            j = 0
            newcertline = ""
            while (j*64 < len(certLine)):
                newcertline += certLine[j*64:(j+1)*64] + "\n"
                j += 1
            certLine = newcertline.replace('\n\n', '\n')
        substrate += certLine
    substrate += "-----END CERTIFICATE-----";
    return substrate;

def readPemFromFile(fileObj):
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
            return substrate

def deColon(b):
    return crypto.b64("".join([chr(int(x, 16)) for x in b.split(":")]))

def toColon(b):
    if len(b) % 2 != 0: return b
    i = 0
    a = ''
    while True:
        a += b[i] + b[i+1]
        if i+1 >= len(b)-1:
            break
        a += ':'
        i += 2
    return a

class CertificateParser(object):
    def __init__(self, raw_der_cert, fingerprint=None, table_name=None, connect=dbconnect.dbconnect(), existing_fields=[], skipfpcheck=False,
                 create_table=False):
        self.gdb, self.gdbc = connect
        if not table_name:
            self.table_name = TABLE_NAME
        else:
            self.table_name = table_name
        self.existing_fields = existing_fields
        self.loadCert(raw_der_cert, fingerprint)
        self.skipfpcheck = skipfpcheck
        self.create_table = create_table

    def loadCert(self, cert, fingerprint, root=False):
        if not cert:
            return
        self.raw_der_cert = cert
        derived_fp = self.addZeroes(cert.get_fingerprint(md='md5').strip(),32) + self.addZeroes(cert.get_fingerprint(md='sha1').strip(), 40)
        if not fingerprint:
            if self.skipfpcheck:
                sys.stderr.write("Warning: missing fingerprint! relying on derived fp %s\n" % derived_fp)
                self.fingerprint = derived_fp
            else:
                raise ValueError, "Must pass in fp"
        else:
            self.fingerprint = self.addZeroes(fingerprint.strip(), 72)
            # sanity check fp
            if derived_fp != self.fingerprint:
                raise ValueError, "Fingerprint does not match. Derived fp is: %s. Given is %s" % (derived_fp, self.fingerprint)
        # indicate this is a cert in a major trust root, i.e. mozilla, ms for now
        self.root = root

    def executeQuery(self, q):
        #sys.stderr.write("Executing: %s" % q)
        try:
            self.gdbc.execute(q)
        except _mysql_exceptions.OperationalError, e:
            # if two instances of this to run at once 
            if "Duplicate column name" in `e`:
                # Another instance already created this column
                return
            raise e

    def addZeroes(self, fp, strlen):
        # make sure leading 0s aren't left out
        if len(fp) >= strlen: return fp
        if len(fp) < strlen:
            num_zeroes = strlen - len(fp)
            a = ''
            for i in xrange(num_zeroes):
                a += '0'
            return a+fp

    def createTableIfMissing(self):
        q = """CREATE TABLE IF NOT EXISTS %s (
                 `cert_fp` binary(36) DEFAULT NULL,
                 `Valid` tinyint(1) DEFAULT NULL,
                 `SHA1_Fingerprint` varchar(256) DEFAULT NULL,
                 `Root` tinyint(1) DEFAULT NULL,
                 `Version` text,
                 `Serial Number` text,
                 `Issuer` text,
                 `Validity:Not Before` text,
                 `Validity:Not After` text,
                 `Subject` text,
                 KEY (`cert_fp`)) ENGINE=MyISAM AUTO_INCREMENT=770819 DEFAULT CHARSET=latin1
             """ % self.table_name
        self.executeQuery(q)

    def addField(self, field):
        q = "ALTER TABLE %s ADD COLUMN `%s` TEXT" % (self.table_name,
                                                     field)
        self.executeQuery(q)

    def addMissingFields(self, field_dict):
        for dkey in field_dict.keys():
            if not dkey in self.existing_fields:
                self.addField(dkey)
                self.existing_fields.append(dkey)

    def loadEntry(self, field_dict, table):
        # string escaping should have already happened but putting here for extra safety
        field_sql = ', '.join("`%s`='%s'" % (self.gdb.escape_string(str(f)), self.gdb.escape_string(str(v))) for  f,v in field_dict.iteritems())
        cert_fp_field = "cert_fp=unhex('%s')" % self.fingerprint
        q = "INSERT IGNORE INTO %s SET %s" % (table, field_sql+", "+cert_fp_field)
        self.executeQuery(q)

    def certFpNeeded(self):
        q = "SELECT count(*) FROM %s WHERE cert_fp = unhex('%s')" % (self.table_name, self.fingerprint)
        self.executeQuery(q)
        # check results
        res = self.gdbc.fetchone()[0]
        if res:
            return False
        return True

    def prepareDictForMySQL(self):
        cert = self.raw_der_cert
        if not cert:
            raise ValueError, "Must supply cert"
        rsa = cert.get_pubkey().get_rsa()

        field_dict = {}

        #  format that consists of the number's length in bytes
        #  represented as a 4-byte big-endian number, and the number
        #  itself in big-endian format, where the most significant bit
        #  signals a negative number

        n = bytes_to_long(rsa.n[4:])
        e = bytes_to_long(rsa.e[4:])
        rsa = RSA.construct((n,e))
        pub = crypto.PublicKey(key=rsa)

        # tracks names that will be loaded to the names table
        names = []

        field_dict['Subject'] = cert.get_subject().as_text().decode('utf8')
        names += self.parseSubject(field_dict['Subject'])
        field_dict['Issuer'] = cert.get_issuer().as_text().decode('utf8')
        field_dict['Serial Number'] = cert.get_serial_number()
        field_dict['Validity:Not Before'] = notBefore=cert.get_not_before().get_datetime()
        field_dict['Validity:Not After'] = cert.get_not_after().get_datetime()
        field_dict['Version'] = cert.get_version()
        field_dict['SHA1_Fingerprint'] = toColon(cert.get_fingerprint(md='sha1'))
        ver = cert.get_version()
        if ver not in VERSION_DICT:
            sys.stderr.write('Warning: Unknown vesion for certificate\n')
            field_dict['Version'] = "Unknown - raw value: %s" % ver
        else:
            field_dict['Version'] = VERSION_DICT[ver]
        if self.root:
            field_dict['Root'] = 1
        else:
            field_dict['Root'] = 0

        c = crypto.Certificate(name=cert.get_subject().as_text().decode('utf8'),
                               pubkey=pub, 
                               serial=cert.get_serial_number(), 
                               notBefore=cert.get_not_before().get_datetime(),
                               notAfter=cert.get_not_after().get_datetime())

        for i in range(cert.get_ext_count()):
            ext = cert.get_ext_at(i)
            eid = ext.get_name()
            if eid == "UNDEF":
                continue
            ev = ext.get_value(flag=X509V3_EXT_ERROR_UNKNOWN)
            critical = ''
            if ext.get_critical():
                critical = "Critical: "
            dkey = self.gdb.escape_string('X509v3 extensions: %s%s' % (critical, eid))
            dval = self.gdb.escape_string(ev.strip().replace('\n', ''))
            if dkey == 'subjectAltName':
                names += self.parseSAN(dval)
            if dkey in field_dict:
                sys.stderr.write('Warning: multiple X.509 extensions with name %s\n' % dkey)
                field_dict[dkey] += " [AND ADDITONAL X509 EXTENSION ENTRY WITH THIS NAME IN CERT] %s" % dval
            else:
                field_dict[dkey] = dval
        return field_dict

    def parseSAN(self, subject_alt_names):
        domain_list = []
        entries = subject_alt_names.split(', ')
        for a in entries:
            split_entry = a.split(':')
            if split_entry[0] != 'DNS' or len(split_entry) != 2:
                continue
            domain_list.append(split_entry[1])
        return domain_list

    def parseSubject(self, subject):
        domain_list = []
        entries = subject.split(', ')
        for a in entries:
            split_entry = a.split('=')
            if split_entry[0] != 'CN' or len(split_entry) != 2:
                continue
            domain_list.append(split_entry[1])
        return domain_list

    def loadNamesToMySQL(self, names):
        """Args: names: [name1, name2, etc]"""
        # tododta validate that it is a real domain name
        for name in names:
            self.loadEntry({'name':name}, table='names')

    def loadToMySQL(self):
        if self.create_table:
            self.createTableIfMissing()
        if not self.certFpNeeded():
            sys.stderr.write("Cert already exists in db with fp %s\n" % self.fingerprint)
            return
        dict_to_load = self.prepareDictForMySQL()
        if not dict_to_load:
            sys.stderr.write("Unable to load certificate with fp %s \n" % self.fingerprint)
            return
        self.addMissingFields(dict_to_load)
        self.loadEntry(dict_to_load, self.table_name)

# Read ASN.1/PEM X.509 certificates on stdin, parse each into plain text,
# then build substrate from it
if __name__ == '__main__':
    import sys
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--table', action='store', dest='table', default=None)
    parser.add_argument('--fp', action='store', dest='fingerprint', default=None)
    parser.add_argument('--pem', action='store_true', dest='pem', default=False)
    parser.add_argument('--test', action='store_true', dest='test', default=False)
    parser.add_argument('--root', action='store_true', dest='root', default=False)
    parser.add_argument('--skip-fp-check', action='store_true', dest='skip_fp_check', default=False)
    parser.add_argument('--create', action='store_true', dest='create_table', default=False)
    args = parser.parse_args()

    if args.test:
        certparser = CertificateParser(None, args.fingerprint, args.table, dbconnect.dbconnecttest(), skipfpcheck=args.skip_fp_check)
    else:
        certparser = CertificateParser(None, args.fingerprint, args.table, skipfpcheck=args.skip_fp_check, create_table=args.create_table)

    if args.pem:
        substrate = readPemFromFile(sys.stdin)
    else:
        substrate = readFromObservatory(sys.stdin)
    if not substrate:
        sys.stderr.write("Bad X.509 format found, unable to parse. Fp (if passed in) is %s \n" % args.fingerprint)
    else:
        cert = X509.load_cert_string(substrate)
        certparser.loadCert(cert, args.fingerprint, args.root)
        certparser.loadToMySQL()
