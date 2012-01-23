#!/usr/bin/env python

create_table = False

import os, time, random, os.path, sys, socket
from dbconnect import dbconnect
db,dbc = dbconnect()

myRand = random.Random(time.time())

from xml.parsers.expat import ParserCreate
parser = ParserCreate()

slash8s = []
prefix = False
status = False

def start_element(name, attrs):
    global prefix,status,new
    if name == "record":
      new = []
    elif name == "prefix":
      prefix = True
    elif name == "status":
      status = True

def end_element(name):
    global prefix,status,new
    if name == "prefix":
      prefix = False
    elif name == "status":
      status = False

def char_data(data):
    global prefix,status,new
    if prefix:
      range,_,mask = data.partition("/")
      #print "got", range, mask
      if mask == "8":
        new.append(int(range))
    elif status and new:
      if data in ["ALLOCATED", "LEGACY"]:
        slash8s.extend(new)

parser.StartElementHandler = start_element
parser.EndElementHandler = end_element
parser.CharacterDataHandler = char_data
parser.ParseFile(open("ipv4-address-space.xml"))

myRand.shuffle(slash8s)
print slash8s
print len(slash8s)

next_s32q = "SELECT s32 FROM spaces WHERE s8 = %d ORDER BY s32 DESC LIMIT 1"
summary_of_s32q = """
SELECT COUNT(hits) AS scans, SUM(hits) as hits 
FROM spaces 
WHERE s8 = %d 
  AND hits IS NOT NULL
"""
abandoned = {}
FUTILE_THRESHOLD = 13                           # thirteen is a lucky number

def getNextTarget():
  # Figure out which subspace we're going to scan next, and tell the database
  # we're doing it.
  dbc.execute("LOCK TABLES spaces WRITE")
  try:
    # walk through the /8s in our particular random order
    for s8 in slash8s:
      dbc.execute(next_s32q % s8) 
      result = dbc.fetchone()
      if result: 
        s32 = result[0] + 1
        # if this /8s is done, move on
        if s32 == 256: continue
        if s32 > 256:
          print "ARG, WTF %r " % (s8,s32)
          sys.exit(1)
        # if we've scanned thirteen targets in this /8, and found no certs, chances
        # are that we aren't going to find any...
        dbc.execute(summary_of_s32q % s8)
        scans, hits = dbc.fetchone()
        if scans >= FUTILE_THRESHOLD and hits == 0:
          if s8 not in abandoned:
            abandoned[s8] = True
            print "Skipping %d.*.*.* (scanned %d subspaces, no hits)" % (s8, FUTILE_THRESHOLD)
          continue
      else:
        s32 = 0
      break
    else:
      print "No more subspaces to scan, exiting"
      sys.exit(0)
    # writing this in with hits = NULL, to indicate that it's a
    # scan-in-progress
    q = "INSERT INTO spaces (s8, s32) VALUES (%d,%d)" % (s8,s32)
    print q
    dbc.execute(q)
    return (s8, "*","*", s32)
  finally:
    dbc.execute("UNLOCK TABLES")

def markDone(target):
  s8, _s16, _s24, s32 = target

  dbc.execute("LOCK TABLES spaces WRITE")
  try:
    hits = 0
    for line in open("range-%d-X-X-%d.txt" % (s8,s32)).readlines():
      if "/open" in line:
        hits += 1
    dbc.execute("UPDATE spaces SET hits=%d WHERE s8=%d AND s32=%d" % (hits,s8,s32))
  finally:
    dbc.execute("UNLOCK TABLES")

def runNmap(address):
  extras = ""
  if address[0] == 192:
    extras = "--exclude 192.168.*.*,192.0.2.*,192.88.99.*"
  elif address[0] == 172:
    extras = "--exclude 172.16.0.0/12"
  elif address[0] ==198:
    extras = "--exclude 198.18.0.0/15"
  elif address[0] == 169:
    extras = "--exclude 169.254.*.*"
  elif address[0] == 130 and address[3] == 84:
    # linux9.ikp.physik.tu-darmstadt.de
    # we received a request to have this machine blocked from scanning
    extras = "--exclude 130.83.133.84"
  if use_ip:
    # Use a different IP address for scanning vs fetching, if we have one
    # available.  This should make us less obnoxious in system logs
    extras += " -S " + use_ip
  command = "nmap -sS -p443 -n -T4 --min-hostgroup 8192 --open -PN %s -oG range-%d-X-X-%d.txt --max-rtt-timeout 500 --randomize-hosts %d.*.*.%d > nmap-out-%d-X-X-%d.txt " % (extras, address[0], address[3], address[0], address[3], address[0], address[3])
  os.system(command)
  pass

def altIP():
  """
  Parse this:

eth0:0    Link encap:Ethernet  HWaddr 00:25:90:39:16:4c  
          inet addr:173.236.34.123  Bcast:173.236.34.127  Mask:255.255.255.248
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          Interrupt:16 Memory:fb5e0000-fb600000 
  """
  lines = os.popen("ifconfig eth0:0").readlines()
  for line in lines:
    if "inet addr" in line:
      entry = line.split()[1]  # 
      _addr,_comma,ip = entry.partition(':')
      try:
        socket.inet_aton(ip)
        print "Using IP address", ip, "for nmapping"
        return ip
      except:
        print "failed to parse ip from\n" + lines
        raise
  print "No alternative IP found"
  return None

use_ip = altIP()

def grabCerts(address):
  command = "python NMapOutputToList.py range-%d-X-X-%d.txt" % (address[0], address[3])
  os.system(command) #

#
# The following test code demonstrates that the control script cleanly walks
# the IPV4 address space. Ommiting all the "bad" class A networks.
#
#
# test = set()
# for host in xrange(0, 6):
#   for pos in xrange(0, 8192):
#     test.add(getNextAddr(host, pos))
#
# if len(test) != 6 * 8192:
#   print "Test failed! number of unique tuples != number expected!"
# else:
#   print "Test succeeded, range generation looks correct"

def main():
  output = open ('Status-%d.txt' % os.getpid(), 'w')
  starttime = time.time()
  scans_done = 0

  while True:
    cur = getNextTarget()
    output.write("starting position: %s %r\n" % (time.asctime(), cur))
    output.flush()
    runNmap(cur)
    output.write("NMap Completed %r\n" % (cur,))
    output.flush()
    grabCerts(cur)
    output.write("certGrab completed %r %s\n" % (cur, time.asctime()))
    output.flush()
    markDone(cur)
    scans_done += 1
    now = time.time()
    days = (now - starttime) / (24. * 3600)
    output.write("%d subspaces scanned in %f days, %f per day" % (scans_done, days, scans_done/days))
    output.flush()

cq = """
CREATE TABLE spaces (
  s8 int NOT NULL, 
  s32 int NOT NULL, 
  hits int default NULL, 
  UNIQUE(s8,s32)
  )
"""
if create_table:
  dbc.execute("DROP TABLE IF EXISTS spaces")
  dbc.execute(cq)
  sys.exit(0)
 
if __name__ == "__main__":
  main()


