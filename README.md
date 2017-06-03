# volatilityVis
Force-directed graph generator for Volatility visualizations
- Requires Python 2.6+, GraphViz, and Volatility

<b> volCombine.py</b>
- v1.3
- Maps pid/ppid connections with process names and usernames.  Combines pslist data with envars, psscan, and/or malfind (if presented as arguments) into one graph.
- Links found in psscan but not psslist will be colored orange.  Start and exit times are now annotated on the node label.
- Usage (pslist.txt is <i>required</i>):  <b><i>volCombine.py pslist.txt</i></b>
- Usage (with optional arguments):  <b><i>volCombine.py pslist.txt envars.txt psscan.txt malfind.txt</i></b>
- pslist shows parent/child process relationships, envars grabs usernames, psscan grabs times, malfind adds colorzation
- Adding malfind.txt will colorize the nodes, but will not add additional label fields
- Colorization is purely based on what's found in malfind, though future node highlighting is on the list
- TODO:  dedup code, classes, colorization of nodes off suspect branches

<b>volPslist.py</b>
- Maps pid/ppid connections with process names.  Same as volCombine.py with only pslist.txt input.
- Usage:  <b><i>volPslist.py pslist.txt</i></b>

![volCombine.py](https://github.com/bonifield/volatilityVis/blob/master/combine-1496507327.png)
