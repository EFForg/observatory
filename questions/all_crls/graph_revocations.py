#!/usr/bin/env python

from dbconnect import dbconnect

db, dbc=dbconnect()

HEADER1 = """newgraph
    xaxis size 5  label : Date
    yaxis size 4 label : Number of revocations
    newcurve
    marktype none
    color 1 0 0
    linetype solid
    pts
"""


all_graph = open("all_revocations.jgraph","w")
all_graph.write(HEADER1)

for year in range(1970,2012):
  for month in range(1,13):
    q = 'SELECT COUNT(*) FROM revoked WHERE `when revoked` >= "%d-%d-01" and `when revoked` < "%d-%d-31 23:59:59"'
    q = q % (year, month, year, month)
    print q
    dbc.execute(q)
    n = int(dbc.fetchone()[0])
    all_graph.write("%f %d\n" % (year + month / 12., n))
