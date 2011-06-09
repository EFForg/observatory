#!/usr/bin/env python

from dbconnect import dbconnect

db, dbc=dbconnect()

for year in range(1970,2012):
  for month in range(1,13):
    q = "SELECT COUNT(*) FROM revoked WHERE `when revoked` >= `%d`-`$d`-01 and `when revoked` < `%d`-`%d`-31 23:59:59"
    q = q % (year, month, year, month)
    dbc.execute(q)
    n = int(dbc.fetchone())
