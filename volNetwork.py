#!/usr/bin/python

#==============
# volCombine.py v0.1
# 16 Aug 2017
# TODO:  add to volCombine as a pseudo-module
#==============

import os,re,sys,time
from itertools import islice

syslist = sys.argv
nets = ''
epoch = int(time.time())

#==============

if len(syslist) > 1:
	for i in syslist:
		if re.search('netscan', i):
			nets = i

else:
	print
	print 'Usage examples:'
	print 'volNetwork.py netscan.txt'
	print
	sys.exit(1)

#==============

dotFile = str('nets-'+str(epoch)+'.dot')
dotOutputFile  = str(dotFile.replace('.dot','.png'))
#circoOutputFile  = str(psli.replace('.txt','-')+enva.replace('.txt','-')+'circo.png')
#neatoOutputFile  = str(psli.replace('.txt','-')+enva.replace('.txt','-')+'neato.png')

#==============

listy = []
dicty = {} # test holdover from copy-pasting code from the main volCombine project

#==============

def funky(d,k,v):
	if k not in d.keys():
		d.setdefault(k,[])
		d[k].append(v)
	elif k in d.keys():
		d[k].append(v)	

def ipv4parser(s,d):
	si = s.split(':')[0]
	sp = s.split(':')[1]
	di = d.split(':')[0]
	dp = d.split(':')[1]
	return [si,sp,di,dp]

def ipv6parser(s,d):
	si = ':'.join(s.split(':')[:-1])
	sp = s.split(':')[-1]
	di = ':'.join(d.split(':')[:-1])
	dp = d.split(':')[-1]
	return [si,sp,di,dp]

def makeGraph():
	print 'Making process-network graph.  This may take a second...'

	if nets:
		with open(nets,'r') as f:
			alpha = re.compile('^[A-Za-z]')
			colon = re.compile('^:')
			for i,line in enumerate(f):
				if i >= 1: # index is 1, line is 2
					l = line.split()
					if alpha.match(l[4]):
						del l[4]
					pro = l[1]
					x = ''
					if re.search('4', pro):
						x = ipv4parser(l[2],l[3])
					elif re.search('6', pro):
						x = ipv6parser(l[2],l[3])
					sip = x[0]
					sport = x[1]
					dip = x[2]
					dport = x[3]
					pid = l[4]
					own = '-'
					try:
						if alpha.match(l[5]):
							own = l[5]
					except:
						pass
					funky(dicty,pid,dip)
#					print '%s %s %s -> %s %s' % (own,sip,sport,dip,dport)
	for k,v in dicty.items():
#		print k,list(set(v))
		for i in list(set(v)):
			listy.append('"%s" -> "%s" [color="purple"];\n' % (k, i))

	with open(dotFile,'w') as o:
		o.write('digraph output {\nnode[shape = Mrecord];\nfontsize=16;\nnodesep=1.5;\nranksep=1;\nrankdir=LR;\n')
		for i in list(set(listy)):
			o.write(i)
		o.write('\n}')
	o.close()

	os.popen('dot -Tpng %s -o %s' % (dotFile, dotOutputFile))
#	os.popen('circo -Tpng %s -o %s' % (dotFile, circoOutputFile))
#	os.popen('neato -Goverlap=scale -Tpng %s -o %s' % (dotFile, neatoOutputFile))
	os.remove(dotFile)
	print 'Made %s' % (dotOutputFile)

#==============

if __name__ == '__main__':
	makeGraph()
