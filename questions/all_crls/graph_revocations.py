#!/usr/bin/env python

from dbconnect import dbconnect

db, dbc=dbconnect()

HEADER_all = """newgraph
    xaxis size 5  label : Date
    max 2012
    yaxis size 4 label : Number of revocations
    newcurve
    marktype none
    color 1 0 0
    linetype solid
    pts
"""


all_graph = open("all_revocations.jgraph","w")
all_graph.write(HEADER_all)

HEADER_by_type = """newgraph
    xaxis size 5  label : Date
    yaxis size 4 label : Number of revocations

"""

curve_desc = """
    newcurve
    marktype none
    color 1 0 0
    linetype solid
    label : %s
    pts
"""    

why_graph = open("by_type.jgraph","w")
why_graph.write(HEADER_by_type)


for year in range(1970,2012):
  for month in range(1,13):
    q = 'SELECT COUNT(*) FROM revoked WHERE `when revoked` >= "%d-%d-01" and `when revoked` < "%d-%d-31 23:59:59"'
    q = q % (year, month, year, month)
    print q
    dbc.execute(q)
    n = int(dbc.fetchone()[0])
    all_graph.write("%f %d\n" % (year + month / 12., n))

q = "SELECT DISTINCT reason FROM revoked"
dbc.execute(q)
results = dbc.fetchall()
print results
for (r,) in results:
  reason = r
  if not r: reason="NULL"
  why_graph.write(curve_desc % reason)
  for year in range(1970,2012):
    for month in range(1,13):
      q = 'SELECT COUNT(*) FROM revoked WHERE `when revoked` >= "%d-%d-01" and `when revoked` < "%d-%d-31 23:59:59" '
      q += 'and reason="%s"' % db.escape_string(reason)
      q = q % (year, month, year, month)
      print q
      dbc.execute(q)
      n = int(dbc.fetchone()[0])
      why_graph.write("%f %d\n" % (year + month / 12., n))
