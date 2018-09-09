# volatilityVis
Force-directed graph generator for Volatility visualizations
- Requires Python 3, GraphViz, and Volatility
- v1.5.1 (08 Sep 2018)
		- totally re-written for Python 3
		- absolutely requires JSON input from Volatility
		- supports Volatility's netscan module
		- no longer requires pslist; everything will be blue if you don't include it though

## Workflow
- collect memory --> run Volatility modules specifying JSON output --> send module output through volCombine

## volCombine.py Overview
	- blue lines mean the link was found in psscan, but not pslist
	- cyan nodes mean the process was found in psscan, but not pslist (future: mangle in psxview)
	- orange nodes mean the process was in malfind, without MZ
	- red nodes mean the process was in malfind, with MZ (4d5a)
	- Maps pid/ppid connections with process names and usernames.  Combines pslist data with envars, psscan, malfind, and/or netscan (if presented as arguments) into one graph.
	- Colorization is purely based on what's found in psscan.txt and malfind.txt, though future node highlighting is on the list

## TODO:  
	- dedup code, better classes, subgrouping
	- add cmdline support
	- add psxview support

## To get JSON output from Volatility:
Add these switches: ```--output=json [module] --output-file=[module]-[youroutputname].json```
The module name MUST be somewhere in the filename you are sending to the script!

## Usage
- Basic with only pslist ```volCombine.py pslist.json```
- With supported inputs:  ```volCombine.py pslist.json envars.json psscan.json malfind.json netscan.json```

## Example output:
![volCombine.py](https://github.com/bonifield/volatilityVis/blob/master/combine-1496526732.png)
