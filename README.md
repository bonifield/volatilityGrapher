# volatilityVis
Force-Directed Graph Generator for Volatility Ouputs
- Requires Python 2.6+, GraphViz, and Volatility

<b> volCombine.py</b>
Maps pid/ppid connections with process names and usernames.  Combines envars and pslist data into one graph.  Usage:  <b><i>volCombine.py envars.txt pslist.txt</i></b>
- TODO:  add psscan times to node label

<b>volPslist.py</b>
Maps pid/ppid connections with process names.

![volCombine.py](https://github.com/bonifield/volatilityVis/blob/master/combine-1495907453.png)
