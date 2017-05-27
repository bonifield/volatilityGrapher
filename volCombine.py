#!/usr/bin/python

#==============
# volCombine.py v1.1
# 27 May 2017
# Feed the script plaintext output from envars and pslist (Volatility modules)
# Usage:  volCombine.py envars.txt pslist.txt psscan.txt
# TODO:  add style="filled", fillcolor="orange" for future node-specific enhancements
#==============

import os,re,sys,time

syslist = sys.argv
psli = ''
enva = ''
pssc = ''
epoch = int(time.time())

#==============

if len(syslist) > 1:
	for i in syslist:
		if re.search('pslist', i):
			psli = i
		if re.search('envar', i):
			enva = i
		if re.search('psscan', i):
			pssc = i

else:
	print
	print 'You need at least pslist.txt and one or more of the following:  envars.txt,  psscan.txt'
	print 'Usage examples:'
	print 'volCombine.py pslist.txt'
	print 'volCombine.py pslist.txt envars.txt'
	print 'volCombine.py pslist.txt envars.txt psscan.txt'
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

	if psli:
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
	else:
		print
		print 'You need pslist.txt at a minumum to run this script!'
		print
		sys.exit(1)

	if enva:
		with open(enva, 'r') as f:
			u = re.compile('USERNAME')
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
		f.close()

	if pssc:
		with open(pssc, 'r') as f:
			pid = ''
			t = ''
			for i, line in enumerate(f):
				if i >= 2:
					l = line.split()
					pid = l[2]
					t = str(l[5]+' '+l[6]+' '+l[7][:3])
					if pid not in dicty.keys():
						dicty.setdefault(pid,[])
						dicty[pid].append(t)
					elif pid in dicty.keys():
						dicty[pid].append(t)
		f.close()

	for k in dicty.keys():
		if len(k) == 0:
			del dicty[k]

	with open(dotFile,'w') as d:
		d.write('digraph output {\nnode[shape = Mrecord];\nfontsize=16;\nnodesep=1.5;\nranksep=1;\nrankdir=LR;')
		for i in list(set(listy)):
			d.write(i)
		if dicty:
			for k in dicty.keys():
				if len(dicty[k]) == 1:
					d.write('"%s" [label="%s\n%s"]' % (k, k, dicty[k][0]))
				elif len(dicty[k]) == 2:
					d.write('"%s" [label="%s\n%s|%s"]' % (k, k, dicty[k][0], dicty[k][1]))
				elif len(dicty[k]) == 3:
					d.write('"%s" [label="%s\n%s|%s|%s"]' % (k, k, dicty[k][0], dicty[k][1], dicty[k][2]))
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
