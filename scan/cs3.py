#!/usr/bin/env python

create_table = False

import os, time, random, os.path, sys
from dbconnect import dbconnect
db,dbc = dbconnect()

#myRand = random.Random(time.time())

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

#myRand.shuffle(slash8s)
print slash8s
print len(slash8s)

liveq = """
SELECT COUNT(hits) AS scans, SUM(hits) as hits 
FROM spaces 
WHERE s8 = %d AND s32 = %d
  AND hits IS NOT NULL
"""

abandoned = {}
def iterateSubspace(s8,s32):
  s32 += 1
  if s32 == 256:
    s32 = 0
    try:
      # this indirection was intended to work with shuffling of slash8s but
      # that has been abandonded since there is no reasnable way to have nextq
      # ORDER BY this scanner's shuffle 
      cur = slash8s.index(s8)
      s8 = slash8s[cur + 1]
      while True:
        dbc.execute(liveq % (s8, s32))
        scans,hits = dbc.fetchone()
        FUTILE_THRESHOLD = 13                           # thirteen is a lucky number

        if scans <= FUTILE_THRESHOLD or hits > 0:
          # if we've scanned thirteen targets in this /8, and found no certs, chances
          # are that we aren't going to find any...
          break
        elif scans > 13:
          if s8 not in abandoned:
            abandoned[s8] = True
            print "Skipping %d.*.*.* (scanned %d subspaces, no hits)" % (s8, FUTILE_THRESHOLD)

        cur = slash8s.index(s8)
        s8 = slash8s[cur + 1]
    except IndexError:
      print "No more subspaces to scan, exiting"
      sys.exit(0)
  return s8,s32


nextq = "SELECT s8,s32 FROM spaces ORDER BY s8,s32 DESC LIMIT 1"

def getNextTarget():
  # Figure out which subspace we're going to scan next, and tell the database
  # we're doing it.
  dbc.execute("LOCK TABLES spaces WRITE")
  try:
    dbc.execute(nextq) 
    result = dbc.fetchone()
    if result:
      s8, s32 = result
      s8, s32 = iterateSubspace(s8, s32)
    else:
      print "Creating first scan entry!"
      s8, s32 = slash8s[0], 0
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
      if "open" in line:
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
  command = "nmap -sS -p443 -n -T4 --min-hostgroup 8192 --open -PN %s -oG range-%d-X-X-%d.txt --max-rtt-timeout 500 --randomize-hosts %d.*.*.%d > nmap-out-%d-X-X-%d.txt " % (extras, address[0], address[3], address[0], address[3], address[0], address[3])
  os.system(command)
  pass

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
  hits int default NULL
  )
"""
if create_table:
  dbc.execute("DROP TABLE IF EXISTS spaces")
  dbc.execute(cq)
  sys.exit(0)
 
if __name__ == "__main__":
  main()


