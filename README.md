# volatilityVis
Force-Directed Graph Generator for Volatility Ouputs
- Requires Python 2.6+, GraphViz, and Volatility

<b> volCombine.py</b>
Maps pid/ppid connections with process names and usernames.  Combines envars and pslist data into one graph.  Usage:  volCombine.py envars.txt pslist.txt
- TODO:  add psscan times to node label

<b>volPslist.py</b>
Maps pid/ppid connections with process names.
