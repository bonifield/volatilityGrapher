#!/usr/bin/python

#==============
# volCombine.py v1.0
# 27 May 2017
# Feed the script plaintext output from envars and pslist (Volatility modules)
# Usage:  volCombine.py envars.txt pslist.txt
# TODO:  add psscan times to node label
#==============

import os,re,sys,time

syslist = sys.argv
psli = ''
enva = ''
epoch = int(time.time())

#==============

if len(syslist) == 3:
	for i in syslist:
		if re.search('pslist', i):
			psli = i
		if re.search('envar', i):
			enva = i
else:
	print
	print 'You need at least the following:  envars.txt and pslist.txt'
	print 'Usage:  volCombine.py envars.txt pslist.txt'
	print
	sys.exit(1)

#==============

dotFile = str('combine-'+str(epoch)+'.dot')
dotOutputFile  = str(dotFile.replace('.dot','.png'))
#circoOutputFile  = str(psli.replace('.txt','-')+enva.replace('.txt','-')+'circo.png')
#neatoOutputFile  = str(psli.replace('.txt','-')+enva.replace('.txt','-')+'neato.png')

#==============

def makeGraph():
	print 'Making combined graph.  This may take a second...'
	listy = []
	dicty = {}
	u = re.compile('USERNAME')
	with open(psli,'r') as f:
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

	with open(enva, 'r') as f:
		pid = ''
		username = ''
		for i,line in enumerate(f):
			if i >= 2:
				if u.findall(line):
					l = line.split()
					pid = l[0]
					username = l[4]
					if pid not in dicty.keys():
						dicty.setdefault(pid,[])
						dicty[pid].append(username)
					elif pid in dicty.keys():
						dicty[pid].append(username)

	for k in dicty.keys():
		if len(k) == 0:
			del dicty[k]

	with open(dotFile,'w') as d:
		d.write('digraph output {\nnode[shape = Mrecord];\nfontsize=16;\nnodesep=0.5;\nrankdir=LR;')
		for i in list(set(listy)):
			d.write(i)

		if dicty:
			for k in dicty.keys():
				if len(dicty[k]) == 1:
					d.write('"%s" [label="%s\n%s"]' % (k, k, dicty[k][0]))
				elif len(dicty[k]) == 2:
					d.write('"%s" [label="%s\n%s|%s"]' % (k, k, dicty[k][0], dicty[k][1]))
		d.write('\n}')
	d.close()

	os.popen('dot -Tpng %s -o %s' % (dotFile, dotOutputFile))
#	os.popen('circo -Tpng %s -o %s' % (dotFile, circoOutputFile))
#	os.popen('neato -Goverlap=scale -Tpng %s -o %s' % (dotFile, neatoOutputFile))
	os.remove(dotFile)
	print 'Made %s' % (dotOutputFile)

#==============

if __name__ == '__main__':
	makeGraph()
