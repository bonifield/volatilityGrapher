# volatilityVis
Force-Directed Graph Generator for Volatility Ouputs
- Requires Python 2.6+, GraphViz, and Volatility

<b> volCombine.py</b>
- v1.2
- Maps pid/ppid connections with process names and usernames.  Combines pslist data with envars, psscan, and/or malfind (if presented as arguments) into one graph.
- Usage (pslist.txt is <i>required</i>):  <b><i>volCombine.py pslist.txt</i></b>
- Usage (with optional arguments):  <b><i>volCombine.py pslist.txt envars.txt psscan.txt malfind.txt</i></b>
- Adding malfind.txt will colorize the nodes, but will not add additional label fields
- TODO:  dedup code, add classes

<b>volPslist.py</b>
- Maps pid/ppid connections with process names.  Same as volCombine.py with only pslist.txt input.
- Usage:  <b><i>volPslist.py pslist.txt</i></b>

![volCombine.py](https://github.com/bonifield/volatilityVis/blob/master/combine-1495981158.png)
