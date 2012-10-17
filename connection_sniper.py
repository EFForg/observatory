#!/usr/bin/env python

import dbconnect
import sys

USER='root'
TIMEOUT=10000

db, dbc = dbconnect.dbconnect()

sql = "show full processlist"
dbc.execute(sql)
res = dbc.fetchall()
for r in res:
    if r[1] == USER and r[4] == 'Sleep' and int(r[5]) > TIMEOUT:
        print "Killing id %s" % r[0]
        sql = "KILL %s" % r[0]
        dbc.execute(sql)
