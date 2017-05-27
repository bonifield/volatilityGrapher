#!/usr/bin/python

#==============
# volPslist.py v1.0
# 27 May 2017
# Feed the script a pslist plaintext output from Volatility
# Usage:  volPslist.py pslist.txt
#==============

import os,sys,time

inputFile = sys.argv[1]
epoch = int(time.time())
dotFile = str('pslist-'+str(epoch)+'.dot')
dotOutputFile = str(dotFile.replace('.dot','.png'))

#==============

def makeGraph():
	listy = []
	dicty = {}
	print 'Making pslist graph.  This may take a second...'
	with open(inputFile,'r') as f:
		k = ''
		v = ''
		for i,line in enumerate(f):
			if i >= 2:
				l = line.split()
				name = l[1]
				pid = l[2]
				ppid = l[3]
				listy.append('"%s" -> "%s" [color="black"];' % (ppid, pid))
				k = pid
				v = name
			if k not in dicty.keys():
				dicty.setdefault(k,[])
				dicty[k].append(v)
			elif k in dicty.keys():
				dicty[k].append(v)

	f.close()

	for key in dicty.keys():
		if len(key) == 0:
			del dicty[key]
		else:
			val = list(set(dicty[key]))
			dicty[key]=val

	with open(dotFile,'w') as d:
		d.write('digraph output {\nnode[shape = Mrecord];\nfontsize=16;\nnodesep=1;\nrankdir=LR;\n')
		for i in list(set(listy)):
			d.write(i)
		if dicty:
			for k in dicty.keys():
				d.write('"%s" [label="%s|%s"];' % (k, k, dicty[k][0]))
		d.write('\n}')
	d.close()

	os.popen('dot -Tpng %s -o %s' % (dotFile, dotOutputFile))
	os.remove(dotFile)
	print 'Made %s' % (dotOutputFile)

#==============

if __name__ == '__main__':
	makeGraph()
