#!/usr/bin/python

#==============
# volCombine.py v1.3.4
# last update:  17 Aug 2018
# Feed the script plaintext output from pslist, envars, psscan, and malfind (Volatility modules)
# Requires pslist.txt at a minimum
# Using both pslist and psscan helps to QUICKLY identify deltas between the two files (unlinked EPROCESS trees are not in pslist)
# --Blue lines mean a new link was found in psscan that wasn't in pslist
# --Cyan nodes mean that process was found in psscan that wasn't in pslist (malfind colors will override this, link line remains blue)
# ----Orange nodes mean the process was found in malfind without MZ (4d5a)
# ----Red nodes mean the process was found in malfind with MZ
# Processing order (not impacted by the order these files are presented to the script):  pslist --> psscan --> envars --> malfind
# Usage:  volCombine.py pslist.txt
# Usage:  volCombine.py pslist.txt envars.txt psscan.txt malfind.txt
# TODO:  dedup code usage, add classes
# - v1.3.3 (16 Aug 2017) - added funky() to remove some reptitive lines
# - v1.3.4 (17 Aug 2018, yes 2018) - added psscan_fixer() for Volatility profile Win10x64_17134
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

listy = []
dicty = {}
d = {}

#==============

def funky(d,k,v):
	if k not in d.keys():
		d.setdefault(k,[])
		d[k].append(v)
	elif k in d.keys():
		d[k].append(v)

def psscan_fixer(p):
	h = [p.index(i) for i in p if re.findall('0x[A-Za-z0-9]{16}', i)]
	return [p[0], ' '.join(p[h[1]+1:]), p[h[1]-2], p[h[1]-1], p[h[1]]]

def makeGraph():
	print 'Making combined graph.  This may take a second...'

	if psli:
		with open(psli,'r') as f:
			for i,line in enumerate(f):
				k = ''
				name = ''
				if i >= 2:
					l = line.split()
					name = l[1]
					pid = l[2]
					ppid = l[3]
					listy.append('"%s" -> "%s";\n' % (ppid, pid))
					k = pid
				funky(dicty,k,name)
		f.close()
	else:
		print
		print 'You need pslist.txt at a minumum to run this script!'
		print
		sys.exit(1)

	if pssc:
		with open(pssc, 'r') as f:
			for i, line in enumerate(f):
				pid = ''
				st = ''
				et = ''
				if i >= 2:
					# for use with Volatility profile Win10x64_17134
					l = psscan_fixer(line.split())
					#l = line.split()
					name = l[1]
					pid = l[2]
					ppid = l[3]
					if len(l) > 5: # if there is a start time
						st = str('Start: '+l[5]+' '+l[6]+' '+l[7][:3])
					if len(l) > 8: # if there is an exit time
						et = str('Exit:  '+l[8]+' '+l[9]+' '+l[10][:3])
					slist = str('"%s" -> "%s";\n' % (ppid, pid))
					try:
						if slist not in listy:
							listy.append('"%s" -> "%s" [color="blue", penwidth=3];\n' % (ppid, pid)) # append a new link if found in psscan but not in pslist
					except:
						pass
					if pid not in dicty.keys():
						dicty.setdefault(pid,[])
						if not et:
							dicty[pid].extend((name, st, 'b'))  # add name and orange flag if the pid is only found in psscan
						else:
							dicty[pid].extend((name, st, et, 'b')) # double parentheses because extend takes one argument
					elif pid in dicty.keys():
						if not et:
							dicty[pid].append(st)
						else:
							dicty[pid].extend((st, et))
		f.close()

	if enva:
		with open(enva, 'r') as f:
			u = re.compile('USERNAME')
			for i,line in enumerate(f):
				pid = ''
				username = ''
				if i >= 2:
					if u.findall(line):
						l = line.split()
						pid = l[0]
						username = ' '.join(l[4:])
						funky(dicty,pid,username)
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
						funky(d,pid,v)
					except:
						pass
		f.close()

	for k in d.keys():
		if len(k) == 0: # delete blank keys
			del d[k]
		val = list(set(d[k])) # make a uniq value list
		if len(val) >= 2: # if 'o' and 'r' are both in the value list
			if 'o' in val:
				val.remove('o') # delete 'o', meaning the node will be prioritized red
		d[k]=val

	for k,v in dicty.items():
		if len(k) == 0: # delete blank keys that make empty nodes on the graph
			del dicty[k]
		if k in d.keys(): # check node for malfind colorization
			dicty[k].append(d[k][0]) # add the malfind node color to the pid (key) values in the main dictionary
		for val in v:
			if len(val) == 0: # remove blank values
				v.remove(val)
		if 'b' in v and 'o' in v: # prioritize orange over blue (psscan-identified link lines will still be blue though)
			v.remove('b')
		if 'b' in v and 'r' in v: # prioritize red over blue
			v.remove('b')

	with open(dotFile,'w') as o:
		o.write('digraph output {\nnode[shape = Mrecord];\nfontsize=16;\nnodesep=1.5;\nranksep=1;\nrankdir=LR;\n')
		for i in list(set(listy)):
			o.write(i)
		if dicty:
			for k in dicty.keys():
				stringy = ''
				blue = str('style="filled", fillcolor="cyan"') # process found in psscan but not pslist
				orange = str('style="filled", fillcolor="orange"') # process in malfind without MZ
				red = str('style="filled", fillcolor="red"') # process in malfind with MZ
				if 'b' in dicty[k] or 'o' in dicty[k] or 'r' in dicty[k]:
					col = ''
					v = ''
					if 'b' in dicty[k]:
						dicty[k].remove('b')
						col = blue
						v = str('|'.join(dicty[k]))
					elif 'o' in dicty[k]:
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
				o.write(stringy+';\n')
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
