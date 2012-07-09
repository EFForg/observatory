from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
from M2Crypto import X509
from datetime import datetime
import crypto
import dbconnect
import MySQLdb
import _mysql_exceptions

X509V3_EXT_ERROR_UNKNOWN = (1L << 16)
TABLE_NAME = 'parsed_certs'

VERSION_DICT = {2: "v3",
                1: "v2",
                0: "v1"}

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
    def __init__(self, raw_der_cert, table_name=TABLE_NAME, connect=dbconnect.dbconnect(), existing_fields=[]):
        self.gdb, self.gdbc = connect
        self.table_name = table_name
        self.existing_fields = existing_fields
        self.loadCert(raw_der_cert)

    def loadCert(self, cert):
        self.raw_der_cert = cert

    def executeQuery(self, q):
        #print "Executing: %s" % q
        try:
            self.gdbc.execute(q)
        except _mysql_exceptions.OperationalError, e:
            # if two instances of this to run at once 
            if "Duplicate column name" in `e`:
                # Another instance already created this column
                return
            raise e

    def createTableIfMissing(self):
        q = """CREATE TABLE IF NOT EXISTS %s (
                 `cert_fp` binary(36) DEFAULT NULL,
                 `valid` tinyint(1) DEFAULT NULL,
                 `SHA1_Fingerprint` varchar(256) DEFAULT NULL,
                 `Version` text,
                 `Serial Number` text,
                 `Signature Algorithm` text,
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

    def loadEntry(self, field_dict):
        # string escaping should have already happened but putting here for extra safety
        field_sql = ', '.join("`%s`='%s'" % (self.gdb.escape_string(str(f)), self.gdb.escape_string(str(v))) for  f,v in field_dict.iteritems())
        q = "INSERT INTO %s SET %s" % (self.table_name, field_sql)
        self.executeQuery(q)
    
    def prepareDictForMySQL(self):
        cert = self.raw_der_cert
        #try:
        rsa = cert.get_pubkey().get_rsa()
        #except ValueError:
        #    return None


        #print str(cert.get_pubkey())

        field_dict = {}

        #  format that consists of the number's length in bytes
        #  represented as a 4-byte big-endian number, and the number
        #  itself in big-endian format, where the most significant bit
        #  signals a negative number

        n = bytes_to_long(rsa.n[4:])
        e = bytes_to_long(rsa.e[4:])
        rsa = RSA.construct((n,e))
        pub = crypto.PublicKey(key=rsa)

        field_dict['Subject'] = cert.get_subject().as_text().decode('utf8')
        field_dict['Issuer'] = cert.get_issuer().as_text().decode('utf8')
        field_dict['Serial Number'] = cert.get_serial_number()
        field_dict['Validity:Not Before'] = notBefore=cert.get_not_before().get_datetime()
        field_dict['Validity:Not After'] = cert.get_not_after().get_datetime()
        field_dict['Version'] = cert.get_version()
        field_dict['SHA1_Fingerprint'] = toColon(cert.get_fingerprint(md='sha1'))
        field_dict['Version'] = VERSION_DICT[cert.get_version()]

        c = crypto.Certificate(name=cert.get_subject().as_text().decode('utf8'),
                               pubkey=pub, 
                               serial=cert.get_serial_number(), 
                               notBefore=cert.get_not_before().get_datetime(),
                               notAfter=cert.get_not_after().get_datetime())

        print str(c)

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
            if dkey in field_dict:
                # todo warning?
                field_dict[dkey] += " [AND ADDITONAL X509 EXTENSION ENTRY WITH THIS NAME IN CERT] %s" % dval
            else:
                field_dict[dkey] = dval
        return field_dict

    def loadToMySQL(self):
        dict_to_load = self.prepareDictForMySQL()
        if not dict_to_load:
            print "Unable to load certificate"
            return
        self.createTableIfMissing()
        self.addMissingFields(field_dict)
        self.loadEntry(field_dict)


# Read ASN.1/PEM X.509 certificates on stdin, parse each into plain text,
# then build substrate from it
if __name__ == '__main__':
    import sys
    
    certCnt = 0

    while 1:
        substrate = readPemFromFile(sys.stdin)
        if not substrate:
            #print "No substrate, breaking"
            break
        cert = X509.load_cert_string(substrate)
        parser = CertificateParser(cert)
        a = parser.prepareDictForMySQL()
        #for f,v in a.iteritems():
        #    print "%s: %s" % (f, v)

        #print "************CERT***********"
        #print cert

        certCnt += 1

        #print '*** %s PEM cert(s) de/serialized' % certCnt
