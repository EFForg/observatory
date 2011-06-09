#!/usr/bin/env python

from dbconnect import dbconnect

db, dbc=dbconnect()

vs = [0.0,1.0]
v2 = [0.0,0.6]
colours = [(r,g,b) for r in vs for g in v2 for b in vs]
colours = colours[:-1] # no white
yellow = colours.index( (1.0,0.6,0.0) )
colours[yellow] = (0.7,0.1,0.1) # red is much better
colours.extend([(0.3,0.3,0.3),(1.0,0.5,0.0)])


HEADER_all = """newgraph
    xaxis size 5  label : Date
    max 2012
    yaxis size 4 label : Number of revocations
    log
    min 0
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
    linetype solid
    color  %d %d %d """
cindex = 0
curve_desc2 = """
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
  why_graph.write(curve_desc % colours[cindex])
  cindex += 1
  why_graph.write(curve_desc2 % reason)
  for year in range(1970,2012):
    for month in range(1,13):
      q = 'SELECT COUNT(*) FROM revoked WHERE `when revoked` >= "%d-%d-01" and `when revoked` < "%d-%d-31 23:59:59" '
      q += 'and reason="%s"' % db.escape_string(reason)
      q = q % (year, month, year, month)
      print q
      dbc.execute(q)
      n = int(dbc.fetchone()[0]
      why_graph.write("%f %d\n" % (year + month / 12., n+1))  # n+1 for log axis
