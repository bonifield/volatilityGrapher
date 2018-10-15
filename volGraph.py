#!/usr/bin/python3

#==============
# volGraph.py v1.5.3
# Last Update:  15 Oct 2018
# Previously known as volCombine.py (last plain output-processing version:  v1.3.4)
# Feed this script JSON output from the following Volatility modules:  pslist, psscan, malfind, envars, netscan
# Using both pslist and psscan helps to QUICKLY identify deltas between the two files
# --Blue lines mean a new link was found in psscan that wasn't in pslist
# --Cyan nodes mean that process was found in psscan that wasn't in pslist (malfind colors will override this, connection line remains blue)
# ----Orange nodes mean the process was found via malfind without MZ (4d5a)
# ----Red nodes mean the process was found via malfind with MZ
# Processing order (not impacted by the order these files are presented to the script):  pslist --> psscan --> malfind --> envars --> netscan --> cmdline
# PSLIST NOT REQUIRED BUT DEFINITELY RECOMMENDED TO BASELINE THE COLORS
# Usage:  volGraph.py pslist.json
# Usage:  volGraph.py pslist.json envars.json psscan.json malfind.json netscan.json cmdline.json
# TODO:  dedup code, psxview ingest, additional module support (apihooks, etc)
# - v1.3.3 (16 Aug 2017) - added funky() to remove some reptitive lines
# - v1.3.4 (17 Aug 2018, yes 2018) - added psscan_fixer() for Win10x Volatility profiles (note - now deprecated)
# - v1.5.1 (08 Sep 2018) - re-wrote in Python 3, with a hard requirement for JSON input (Volatilty switches: --output=json [module] --output-file=[module]-[youroutputname].json)
#			- added netscan support
#			- added a main class to handle the heavy lifting, make future object calls easier
#			- cleaner ingest, LOTS of code deduplication (more to come)
#			- NO LONGER REQUIRES PSLIST; omitting pslist will make all of the lines and nodes blue though :)
# - v1.5.2 (09 Oct 2018) - fixed a major bug where PIDs would not display on the nodes...  now they do!
# - v1.5.3 (15 Oct 2018) - added cmdline support, fixed this description
#==============

import json,os,re,sys,time

#==============

syslist = sys.argv
psli = None
pssc = None
malf = None
enva = None
nets = None
cmdl = None
epoch = str(int(time.time()))

dotFile = str('volGraph-{}.dot'.format(epoch))
dotImage = str('volGraph-{}-dot.png'.format(epoch))
circoImage = str('volGraph-{}-circo.png'.format(epoch))
neatoImage = str('volGraph-{}-neato.png'.format(epoch))

#==============

def opener(o):
	try:
		with open(o, 'r') as f:
			data = json.load(f)
		f.close()
		return data
	except Exception as e:
		print(str(e))
		print('ERROR:  All inputs must be JSON.')
		print('USAGE:  volGraph.py some-module-output.json some-other-module.json yet-another-module.json etc...')
		print('Supports the following Volatility module output in JSON format:  pslist, psscan, malfind, envars, netscan, cmdline')
		print('Use the following switches with Volatility:  "--output=json [module] --output-file=[module]-[youroutputname].json"')
		sys.exit(1)

if len(syslist) > 1:
	for i in syslist[1:]:
		if re.search('pslist', i):
			psli = opener(i)
		if re.search('psscan', i):
			pssc = opener(i)
		if re.search('malf', i):
			malf = opener(i)
		if re.search('envar', i):
			enva = opener(i)
		if re.search('netsc', i):
			nets = opener(i)
		if re.search('cmdline', i):
			cmdl = opener(i)

dicty = {"pslist":psli,"psscan":pssc,"malfind":malf,"envars":enva,"netscan":nets,"cmdline":cmdl}

#==============

class Combiner(object):
	def __init__(self, idict):
		""" initialize all values and individual dictionaries which will be combined into one cohesive data structure """
		self.idict = idict
		self.d = {}
		self.l = []
		if idict["pslist"]:
			self.pslist = idict["pslist"]["rows"]
		else:
			self.pslist = None
		if idict["psscan"]:
			self.psscan = idict["psscan"]["rows"]
		else:
			self.psscan = None
		if idict["malfind"]:
			self.malfind = idict["malfind"]["rows"]
		else:
			self.malfind = None
		if idict["envars"]:
			self.envars = idict["envars"]["rows"]
		else:
			self.envars = None
		if idict["netscan"]:
			self.netscan = idict["netscan"]["rows"]
		else:
			self.netscan = None
		if idict["cmdline"]:
			self.cmdline = idict["cmdline"]["rows"]
		else:
			self.cmdline = None

	def dgen(self, d,k,v):
		""" worker function to generate the main combined dictionary as directed by dworker """
		if k not in d.keys():
			d.setdefault(k,{})
			d[k].update(v)
		elif k in d.keys():
			# remove psscan colors if pslist already found something
			if "color" in d[k].keys():
				if d[k]["color"] == "black":
					if "color" in v.keys():
						if v["color"] == "blue":
							del v["color"]
					if "fillcolor" in v.keys():
						if v["fillcolor"] == "cyan":
							del v["fillcolor"]
			d[k].update(v)

	def dworker(self):
		""" generates the main combined dictionary as directed by data """
		""" {pid:{subkey:subvalue}} """
		if self.pslist:
			for i in self.pslist:
				self.dgen(self.d, i[2], {"name":i[1], "ppid":i[3], "created":i[8], "color":"black"})
		if self.psscan:
			for i in self.psscan:
				self.dgen(self.d, i[2], {"name":i[1], "ppid":i[3], "created":i[5], "color":"blue", "fillcolor":"cyan"})
				if len(i[6]) > 0:
					self.d[i[2]]["exited"]=i[6]
		if self.malfind:
			for i in self.malfind:
				self.dgen(self.d, i[1], {"protection":i[4], "bytes":i[6][:10], "fillcolor":"orange"})
				if re.search('4d5a', i[6]):
					self.d[i[1]]["fillcolor"]="red"
		if self.envars:
			for i in self.envars:
				if i[3] == "USERNAME":
					self.dgen(self.d, i[0], {"username":i[4]})
		if self.netscan:
			for i in self.netscan:
				self.dgen(self.d, i[5], {"proto":i[1], "localaddr":i[2], "foreignaddr":i[3], "state":i[4], "conn-owner":i[6], "conn-created":i[7]})
		if self.cmdline:
			for i in self.cmdline:
				if len(i[2]) > 0:
					cfix = i[2].replace("\"", "").replace("\\", "\\\\").replace("{", "\{").replace("}", "\}")
					self.dgen(self.d, i[1], {"cmdline":cfix})

	def data(self):
		""" creates and returns the dictionary """
		self.dworker()
		return self.d

	def lworker(self):
		""" generates the list of connections as directed by listy """
		for k,v in self.data().items():
			try:
				if v['color'] == 'blue':
					self.l.append('"{}" -> "{}" [color="{}", penwidth=3]'.format(str(v.get("ppid")), str(k), str(v.get("color"))))
				else:
					self.l.append('"{}" -> "{}" [color="{}"]'.format(str(v.get("ppid")), str(k), str(v.get("color"))))
			except:
				self.l.append('"{}" -> "{}"'.format(str(v.get("ppid")), str(k)))

	def listy(self):
		""" creates and returns the list of connections based on the combined dictionary """
		self.lworker()
		return self.l

	def label(self):
		for k,v in self.data().items():
			# remove keys not to be displayed on individual nodes
			try:
				del v['color']
			except:
				pass
			try:
				del v['ppid']
			except:
				pass
			try:
				del v['bytes']
			except:
				pass
			x = None
			if 'fillcolor' in v.keys():
				x = '"{}" [style="filled", fillcolor="{}", label="{}"]'.format(str(k), str(v.pop('fillcolor')), str(str(k)+'|'+'|'.join([': '.join(t) for t in [(str(key),str(val)) for key,val in v.items()]])))
			else:
				try:
					x = '"{}" [label="{}"]'.format(str(k), str(str(k)+'|'+'|'.join([': '.join(t) for t in [(str(key),str(val)) for key,val in v.items()]])))
				except Exception as e:
#					x = str(e)
					x = '"{}" [label="{}"]'.format(str(k), str(e))

			if x is not None:
				yield(x)

	def __repr__(self):
		return str('pslist: {}\tpsscan: {}\tmalfind:{}\tenvars: {}\tnetscan: {}\tcmdline: {}'.format(type(self.pslist).__name__, type(self.psscan).__name__, type(self.malfind).__name__, type(self.envars).__name__, type(self.netscan).__name__, type(self.cmdline).__name__))

#==============

# instantiate the class
c = Combiner(dicty)

def makeGraph():
	print('Making {}'.format(dotFile))
	with open(dotFile,'w') as o:
		o.write('digraph output {\nnode[shape = Mrecord];\nfontsize=16;\nnodesep=1.5;\nranksep=1;\nrankdir=LR;\n')
		for i in c.listy():
			o.write(i+';\n')
		for i in c.label():
			o.write(i+';\n')
		o.write('\n}')
	o.close()
	print('Making output images...  these may take a minute to render.')
	try:
		# UNCOMMENT THE FORMATS YOU WANT TO SEE OUTPUT
		# CLASSIC DOT IMAGE OUTPUT
		os.popen('dot -Tpng {} -o {}'.format(dotFile, dotImage))
		# CIRCO IMAGE OUTPUT
		#os.popen('circo -Tpng {} -o {}'.format(dotFile, circoImage))
		#print('Made {}'.format(circoImage))
		# NEATO IMAGE OUTPUT
		#os.popen('neato -Goverlap=scale -Tpng {} -o {}'.format(dotFile, neatoImage))
		#print('Made {}'.format(neatoImage))
	except:
		print('ERROR:  "dot", "circo", and/or "neato" not found via path variable - is GraphViz installed on this system?')
		sys.exit(5)
	# comment this line to preserve the dot-formatted text file used to generate the images via GraphViz
	# os.remove(dotFile)
	print('Made {}'.format(dotImage))

#==============

if __name__ == '__main__':
	makeGraph()
