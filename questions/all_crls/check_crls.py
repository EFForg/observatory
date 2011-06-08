#!/usr/bin/env python

import MySQLdb,os.path, sys
from subprocess import PIPE, Popen
from urllib import urlretrieve
import sys
sys.path.append("..")
from dbconnect import dbconnect
db,dbc = dbconnect()

CMD = ["openssl", "crl", "-noout", "-text", "-inform", "der", "-in"]

def fetch_crl(uri):
  # Note that this is lazy about fetching CRLs; if they need to be fresh they 
  # should be deleted and re-fetched
  print "Fetching", uri
  if uri.startswith("ldap:"): return
  fn = uri.replace(os.path.sep,"-")
  if not os.path.isfile(fn):
    try:
      filen, headers = urlretrieve(uri, fn)
    except IOError,e:
      print "ERROR FETCHING", uri
      print e
      return
    assert fn == filen

  cmd = CMD + [fn]
  proc = Popen(cmd, stdout=PIPE, stdin=PIPE)
  stdout, stderr = proc.communicate()
  if stderr:
    print "ERROR reading CRL:"
    print stderr
    sys.exit(1)
  details = {"uri" : uri}
  ready_for_reason = False
  #Example: 
  #    Serial Number: 42858298
  #      Revocation Date: Jun 29 14:50:12 2005 GMT
  #      CRL entry extensions:
  #          X509v3 CRL Reason Code: 
  #              Superseded

  for line in stdout.split("\n"):
    l = line.strip()
    if l.startswith("Serial Number: "):
      if details:
        insert_revocation_row(details)
        details = {"uri" : uri}
      details["sn"] = l.partition("Serial Number: ")[2]
    elif l.startswith("Revocation Date: "):
      details["date"] = l.partition("Revocation Date: ")[2]
    elif l.startswith("X509v3 CRL Reason Code:"):
      ready_for_reason=True
    elif ready_for_reason:
      details["reason"]=l
      ready_for_reason = False
    else:
      print "Unknown:", l
      
  if details:
    insert_revocation_row(details)

def insert_revocation_row(d):

  uri = "'%s'" % db.escape_string(d["uri"])
  sn = "'%s'" % db.escape_string(d["sn"])
  ts = "STR_TO_DATE('"+db.escape_string(d["date"])+"','%b %d %H:%i:%s %Y')" 
  if "reason" in d :
    reason = "'%s'" % db.escape_string(d["reason"])
  else:
    reason = "NULL"
    
  q = "INSERT INTO revoked VALUE (%s, %s, %s, %s)" % (uri, sn, ts, reason)
                                       
  print q
  dbc.execute(q)
  

def mk_revoked_table():
  q = "DROP TABLE IF EXISTS revoked"
  print q
  dbc.execute(q)
  q = "CREATE TABLE revoked (uri text, `Serial Number` varchar(100), when datetime, reason text)"
  print q
  dbc.execute(q)
  q = "CREATE INDEX sn ON revoked(`Serial Number`)"
  q = "CREATE INDEX r ON revoked(`Reason`)"
  print q
  dbc.execute(q)


def main():
  mk_revoked_table()
  q = """
  select distinct `X509v3 extensions:X509v3 CRL Distribution Points`
  from valid_certs"""
  dbc.execute(q)
  results = dbc.fetchall()
  fetched = {}
  for (crl,) in results:
    print crl
    if crl:
      for word in crl.split():
        if word.startswith("URI==="):
          uri = word.partition("URI===")[2]
          print "uri", uri
          if uri not in fetched:
            fetch_crl(uri)
            fetched[uri] = True

if __name__ == "__main__":
  main()
