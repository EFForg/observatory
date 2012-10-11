#!/usr/bin/env python

"""
Usage:

./schemacopy.py database1 database2

Where database1 is an existing mysql database, and database2 is a new one that will 
have the same schema as database1. An error is given if database2 already exists, 
or if database1 does not exist. Note this does NOT copy views.
"""

import dbconnect
import _mysql_exceptions
import sys

db, dbc = dbconnect.dbconnect()

def query(sql, args=None):
    #print "Executing: %s" % (sql % args)
    try:
        if args:
            dbc.execute(sql, args)
        else:
            dbc.execute(sql)
    except _mysql_exceptions.OperationalError, e:
        # if two instances of this to run at once 
        if "Duplicate column name" in `e`:
            # Another instance already created this column
            return
        raise e

def checkDbExistence(dbname):
    query("SHOW DATABASES")
    for db in dbc.fetchall():
        if db[0] == dbname:
            return True
    return False

def makeDb(dbname):
    query("CREATE DATABASE IF NOT EXISTS %s" % dbname)

def copySchema(old_db, new_db):
    query("USE %s" % new_db)
    query("SHOW TABLES IN %s" % old_db)
    tables = dbc.fetchall()
    for table in tables:
        query("SHOW CREATE TABLE %s.%s" % (old_db, table[0]))
        # filter out views
        res = dbc.fetchone()[1]
        if res.startswith("CREATE TABLE"):
            query(res)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print "Usage: ./schemacopy.py database1 database2"
        sys.exit(1)
    old_db = sys.argv[1]
    new_db = sys.argv[2]
    if not checkDbExistence(old_db):
        print "Error: old db not found"
        sys.exit(1)
    if checkDbExistence(new_db):
        print "Error: new db already exists"
        sys.exit(1)
    makeDb(new_db)
    print "Copy schema from %s to %s" % (old_db, new_db)
    copySchema(old_db, new_db)
