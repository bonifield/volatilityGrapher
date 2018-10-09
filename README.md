# volatilityGrapher
Force-directed graph generator for Volatility visualizations
- Requires Python 3, GraphViz, and Volatility
- v1.5.2 (09 Oct 2018)
	- totally re-written for Python 3
	- absolutely requires JSON input from Volatility
	- supports Volatility's netscan module
	- no longer requires pslist; everything will be blue if you don't include it though
	- ezVolGraph.sh is a quick-and-dirty way to automate the JSON and graph-making process (see below under Usage)
	- fixed a bug where PIDs wouldn't display properly on nodes

## Workflow
- collect memory --> run Volatility modules specifying JSON output --> send module output through volGraph.py

## volGraph.py Overview
- blue lines and cyan nodes mean the relationship was found in psscan, but not pslist
- orange nodes mean the process was in malfind, without MZ
- red nodes mean the process was in malfind, with MZ (4d5a)
- Colorization is purely based on what's found in psscan.json and malfind.json

## TODO:  
- dedup code, better classes, subgrouping
- add cmdline support
- add psxview support

## To get JSON output from Volatility:
Add these switches: ```--output=json [module] --output-file=[module]-[youroutputname].json```

## Usage
### The module name for each JSON file MUST be somewhere in the filename!
- Basic with only pslist ```volGraph.py pslist.json```
- With supported inputs:  ```volGraph.py pslist.json envars.json psscan.json malfind.json netscan.json```
- Easy mode, use the provided Bash script with a memory capture and a Volatility profile to generate all of the necessary files:  ```ezVolGraph.sh somefile.dmp profile```

## Example output:
### Powershell Empire:
![volGraph.py](https://github.com/bonifield/volatilityGrapher/blob/master/sampledata/volGraph-1539122826-dot.png)
### Metasploit Shenanigans:
![volGraph.py](https://github.com/bonifield/volatilityGrapher/blob/master/sampledata/combine-1496526732.png)

