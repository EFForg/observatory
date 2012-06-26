# Read ASN.1/PEM X.509 certificates on stdin, parse each into plain text,
# then build substrate from it
import sys, string, base64, binascii
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error

# Would be autogenerated from ASN.1 source by a ASN.1 parser
# X.509 spec (rfc2459)

MAX = 64  # XXX ?

class DirectoryString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('teletexString', char.TeletexString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('printableString', char.PrintableString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('universalString', char.UniversalString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('utf8String', char.UTF8String().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('bmpString', char.BMPString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('ia5String', char.IA5String().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))) # hm, this should not be here!? XXX
        )

class AttributeValue(DirectoryString): pass

class AttributeType(univ.ObjectIdentifier): pass

class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('value', AttributeValue())
        )

class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()

class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()

class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('', RDNSequence())
        )
                          
class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Null())
        # XXX syntax screwed?
#        namedtype.OptionalNamedType('parameters', univ.ObjectIdentifier())
        )

class Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', univ.Boolean('False')),
        namedtype.NamedType('extnValue', univ.OctetString())
        )

class Extensions(univ.SequenceOf):
    componentType = Extension()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)

class SubjectPublicKeyInfo(univ.Sequence):
     componentType = namedtype.NamedTypes(
         namedtype.NamedType('algorithm', AlgorithmIdentifier()),
         namedtype.NamedType('subjectPublicKey', univ.BitString())
         )

class UniqueIdentifier(univ.BitString): pass

class Time(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('utcTime', useful.UTCTime()),
        namedtype.NamedType('generalTime', useful.GeneralizedTime())
        )
    
class Validity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('notBefore', Time()),
        namedtype.NamedType('notAfter', Time())
        )

class CertificateSerialNumber(univ.Integer): pass

class Version(univ.Integer):
    namedValues = namedval.NamedValues(
        ('v1', 0), ('v2', 1), ('v3', 2)
        )

class TBSCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', Version('v1', tagSet=Version.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))),
        namedtype.NamedType('serialNumber', CertificateSerialNumber()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('issuer', Name()),
        namedtype.NamedType('validity', Validity()),
        namedtype.NamedType('subject', Name()),
        namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType('issuerUniqueID', UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('subjectUniqueID', UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('extensions', Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)))
        )

class Certificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertificate', TBSCertificate()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', univ.BitString())
        )

# end of ASN.1 data structures

certType = Certificate()
#octetType = univ.OctetString()

# Read PEM certs from stdin and print them out in plain text

stSpam, stHam, stDump = 0, 1, 2
state = stSpam
certCnt = 0

# Convert between OID and String Representation
rdn_type_dict = {(2,5,4,6): "C",
                 (2,5,4,10): "O",
                 (2,5,4,11): "OU",
                 (2,5,4,3): "CN",
                 (2,5,4,8): "ST",
                 (2,5,4,7): "L"}

def parseDN(seq):
    full_rdn = []
    for i in range(len(seq)):
        rdn = seq.getComponentByPosition(i).getComponentByPosition(0)
        printable_rdn = rdn.getComponentByPosition(1).getComponentByPosition(1)
        rdn_type = rdn.getComponentByPosition(0)
        # use string representation if we have one
        if rdn_type in rdn_type_dict:
            rdn_type = rdn_type_dict[rdn_type]
        full_rdn.append((rdn_type, printable_rdn))
    return full_rdn


for certLine in sys.stdin.readlines():
    certLine = string.strip(certLine)
    if state == stSpam:
        if state == stSpam:
            if certLine == '-----BEGIN CERTIFICATE-----':
                certLines = []
                state = stHam
                continue
    if state == stHam:
        if certLine == '-----END CERTIFICATE-----':
            state = stDump
        else:
            certLines.append(certLine)
    if state == stDump:
        substrate = ''
        for certLine in certLines:
            substrate = substrate + base64.b64decode(certLine)

        cert = decoder.decode(substrate, asn1Spec=certType)[0]
        #print cert.prettyPrint()
        
        # Dan's parsing code
        TBS = cert.getComponentByPosition(0)
        print 'Version: %s' % TBS.getComponentByName('version')
        print 'Serial Number: %s' % TBS.getComponentByName('serialNumber')
        # parse issuer
        issuer = TBS.getComponentByName('issuer').getComponentByPosition(0)
        issuer_full_rdn = parseDN(issuer)
        issuer_str = ', '.join(["%s=%s" % (a,b) for (a, b) in issuer_full_rdn])
        print "Full Issuer: %s" % issuer_str
        # parse subject
        # todo get teletexString *.google.com to work
        subject = TBS.getComponentByName('subject').getComponentByPosition(0)
        subject_full_rdn = parseDN(subject)
        subject_str = ', '.join(["%s=%s" % (a,b) for (a, b) in subject_full_rdn])
        print "Full Subject: %s" % subject_str
        
        # validity
        validity_before = TBS.getComponentByName('validity').getComponentByPosition(0).getComponentByPosition(0)
        validity_after = TBS.getComponentByName('validity').getComponentByPosition(1).getComponentByPosition(0)
        print "Valid not before: %s" % validity_before
        print "Valid not after: %s" % validity_after

        # subject public key info
        subject_public_key_info = TBS.getComponentByName('subjectPublicKeyInfo')
        subject_public_key_alg = subject_public_key_info.getComponentByPosition(0).getComponentByPosition(0)
        # todo parameters?
        subject_public_key = subject_public_key_info.getComponentByPosition(1)
        print "Public Key Algorithm: %s" % subject_public_key_alg
        # todo uncomment, handle public key bitstring
        #print "Public Key: %s" % subject_public_key

        # extensions
        extensions = TBS.getComponentByName('extensions')
        for idx in range(len(extensions)):
            extn = extensions.getComponentByPosition(idx)
            extn_id = extn.getComponentByPosition(0)
            print extn_id
            if extn.getComponentByPosition(1):
                print "This extension is critical!"
            if len(extn) != 3:
                print "Error"
            extn_value = extn.getComponentByPosition(2)
            #print extn_value.prettyPrint()
            try:
                extn_string = decoder.decode(extn_value) #, asn1Spec=univ.OctetString())
                print extn_string
            except:
                #extn_string = decoder.decode(extn_value, asn1Spec=univ.Any)
                #print extn_string
                print "Error with extension %s" % extn_id
            #print extn_string
#            print extn_string[0]
            #print extn_value
            #for let in extn_value:
            #    print ord(let)
            #break
            #print extn_value.asNumbers()
            
                                
            #print hex(extn_value)
            #print binascii.a2b_hex(str(extn_value))

                

        #print extensions

        #print TBS[0]
        # for idx in range(len(TBS)):
        #    print "%s: %s" % (TBS.getTypeByPosition(idx), TBS.getComponentByPosition(idx))
           #TBS.getNameByPosition(idx) # this doesn't work
        
        assert encoder.encode(cert) == substrate, 'cert recode fails'
        
        certCnt = certCnt + 1
        state = stSpam

print '*** %s PEM cert(s) de/serialized' % certCnt

