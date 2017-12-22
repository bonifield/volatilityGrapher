# volatilityVis
Force-directed graph generator for Volatility visualizations
- Requires Python 2.6+, GraphViz, and Volatility

## volCombine.py
- v1.3
  - blue lines mean the link was found in psscan, but not pslist
  - cyan nodes mean the process was found in psscan, but not pslist
  - orange nodes mean the process was in malfind, without MZ
  - red nodes mean the process was in malfind, with MZ (4d5a)
- Maps pid/ppid connections with process names and usernames.  Combines pslist data with envars, psscan, and/or malfind (if presented as arguments) into one graph.
- Colorization is purely based on what's found in psscan.txt and malfind.txt, though future node highlighting is on the list
- TODO:  dedup code, classes, colorization of nodes off suspect branches (or subgroup suspect branches altogether)

## Usage
- Simple (pslist.txt is <i>required</i>):  ```volCombine.py pslist.txt```
- With optional inputs:  ```volCombine.py pslist.txt envars.txt psscan.txt malfind.txt```

## Example output:
![volCombine.py](https://github.com/bonifield/volatilityVis/blob/master/combine-1496526732.png)
