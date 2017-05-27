# volatilityVis
Force-Directed Graph Generator for Volatility Ouputs
- Requires Python 2.6+, GraphViz, and Volatility

<b> volCombine.py</b>
Maps pid/ppid connections with process names and usernames.  Combines pslist data with envars and/or psscan (if presented as arguments) into one graph.
- Usage (pslist.txt is <u>required</u>:  <b><i>volCombine.py pslist.txt</i></b>
- Usage (with optional arguments):  <b><i>volCombine.py pslist.txt envars.txt psscan.txt</i></b>
- TODO:  colorize individual nodes

<b>volPslist.py</b>
Maps pid/ppid connections with process names.
- Usage:  <b><i>volPslist.py pslist.txt</i></b>

![volCombine.py](https://github.com/bonifield/volatilityVis/blob/master/combine-1495923844.png)
