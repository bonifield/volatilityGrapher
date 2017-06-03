#!/usr/bin/python

#==============
# volCombine.py v1.3
# 3 June 2017
# Feed the script plaintext output from pslist, envars, psscan, and malfind (Volatility modules)
# Requires pslist.txt at a minimum
# Orange lines mean a new link was found in psscan that wasn't in pslist
# Usage:  volCombine.py pslist.txt
# Usage:  volCombine.py pslist.txt envars.txt psscan.txt malfind.txt
# TODO:  dedup code usage, add classes
#==============

import os,re,sys,time
from itertools import islice

syslist = sys.argv
psli = ''
enva = ''
pssc = ''
malf = ''
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
		if re.search('malf', i):
			malf = i

else:
	print
	print 'You need at least pslist.txt and one or more of the following:  envars.txt, psscan.txt, malfind.txt'
	print 'Usage examples:'
	print 'volCombine.py pslist.txt'
	print 'volCombine.py pslist.txt envars.txt'
	print 'volCombine.py pslist.txt envars.txt psscan.txt'
	print 'volCombine.py pslist.txt envars.txt psscan.txt malfind.txt'
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
	d = {}

	if psli:
		with open(psli,'r') as f:
			k = ''
			name = ''
			for i,line in enumerate(f):
				if i >= 2:
					l = line.split()
					name = l[1]
					pid = l[2]
					ppid = l[3]
					listy.append('"%s" -> "%s";\n' % (ppid, pid))
					k = pid
				if k not in dicty.keys():
					dicty.setdefault(k,[])
					dicty[k].append(name)
				elif k in dicty.keys():
					dicty[k].append(name)
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
			st = ''
			et = ''
			for i, line in enumerate(f):
				if i >= 2:
					l = line.split()
					pid = l[2]
					ppid = l[3]
					st = str('Start: '+l[5]+' '+l[6]+' '+l[7][:3])
					if len(l) > 8: # if there is an exit time, save the time as et
						et = str('Exit:  '+l[8]+' '+l[9]+' '+l[10][:3])
					slist = str('"%s" -> "%s";\n' % (ppid, pid))
					try:
						if slist not in listy:
							listy.append('"%s" -> "%s" [color="orange", penwidth=3];\n' % (ppid, pid)) # append a new link if found in psscan but not in pslist
					except:
						pass
					if pid not in dicty.keys():
						dicty.setdefault(pid,[])
						if not et:
							dicty[pid].append(st)
						else:
							dicty[pid].extend((st, et)) # double parentheses because extend takes one argument
					elif pid in dicty.keys():
						if not et:
							dicty[pid].append(st)
						else:
							dicty[pid].extend((st, et))
		f.close()

	if malf:
		with open(malf, 'r') as f:
			p = re.compile('Process')
			mz = re.compile('4d5a', re.I)
			for line in f:
				if p.match(line):
					try:
						l = line.split()
						pid = l[3]
						v = ''
						a = str(''.join(list(islice(f, 4)))).replace('\r\n','').replace(' ','') # islice returns line + 4 as an object, show that object as a list, wrangle it into form
						if mz.findall(a):
							v = str('r')
						else:
							v = str('o')
						if pid not in d.keys():
							d.setdefault(pid, [])
							d[pid].append(v)
						elif pid in d.keys():
							d[pid].append(v)
					except:
						pass
		f.close()

	for k in d.keys():
		if len(k) == 0:
			del d[k]
		val = list(set(d[k]))
		if len(val) >= 2:
			if 'o' in val:
				val.remove('o')
		d[k]=val

	for k,v in dicty.items():
		if len(k) == 0: # delete blank keys that make empty nodes on the graph
			del dicty[k]
		if k in d.keys():
			dicty[k].append(d[k][0])
		for val in v:
			if len(val) == 0: # remove blank values
				v.remove(val)

	d = {} # clean dict

	with open(dotFile,'w') as o:
		o.write('digraph output {\nnode[shape = Mrecord];\nfontsize=16;\nnodesep=1.5;\nranksep=1;\nrankdir=LR;\n')
		for i in list(set(listy)):
			o.write(i)
		if dicty:
			for k in dicty.keys():
				stringy = ''
				orange = str('style="filled", fillcolor="orange"')
				red = str('style="filled", fillcolor="red"')
				if 'o' in dicty[k] or 'r' in dicty[k]:
					col = ''
					v = ''
					if 'o' in dicty[k]:
						dicty[k].remove('o')
						col = orange
						v = str('|'.join(dicty[k]))
					elif 'r' in dicty[k]:
						dicty[k].remove('r')
						col = red
						v = str('|'.join(dicty[k]))
					if len(dicty[k]) == 0:
						stringy = '"%s" [label="%s", %s]' % (k, k, col)
					elif len(dicty[k]) >= 1:
						stringy = '"%s" [label="%s|%s", %s]' % (k, k, v, col)
				else:
					v = str('|'.join(dicty[k]))
					if len(dicty[k]) == 0:
						stringy = '"%s" [label="%s"]' % (k, k)
					elif len(dicty[k]) >= 1:
						stringy = '"%s" [label="%s|%s"]' % (k, k, v)
				o.write(stringy+'\n')
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
