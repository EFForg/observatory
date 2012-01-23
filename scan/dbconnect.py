#!/usr/bin/env python
import MySQLdb
import time
from subprocess import Popen, PIPE

try:    from db_private import DB_USER
except: DB_USER = "root" 

try:    from db_private import DB_PASS
except: DB_PASS = "root"                # change this for your local setup

try:    from db_private import DB_NAME  
except: DB_NAME = "scanners"

def dbconnect():
  try:
    db = MySQLdb.connect(user=DB_USER, passwd=DB_PASS, db=DB_NAME)
    dbc = db.cursor()
  except:
    from db_private import db_tunnel_cmd, DB_PORT
    print "Tunnelling:", db_tunnel_cmd
    ssh = Popen(db_tunnel_cmd,stdin=PIPE,stdout=PIPE, stderr=PIPE)
    time.sleep(5)
    try:
      db = MySQLdb.connect(user=DB_USER, passwd=DB_PASS, db=DB_NAME, port=DB_PORT, host="127.0.0.1")
      dbc = db.cursor()
    except:
      out, err = ssh.communicate()
      print "stdout\n" + out
      print "stderr\n" + err
      raise
  return db,dbc
