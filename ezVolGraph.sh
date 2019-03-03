#!/bin/bash
# last updated 01 Mar 2019, use with 1.5.x of volGraph.py

echo
echo "Usage:  ezvol.sh somefile.dmp profile"
echo "Running.  This may take a minute..."
vol.py -f $1 --profile=$2 --output=json pslist --output-file=$1-$2-pslist.json 2> /dev/null
vol.py -f $1 --profile=$2 --output=json psscan --output-file=$1-$2-psscan.json 2> /dev/null
vol.py -f $1 --profile=$2 --output=json envars --output-file=$1-$2-envars.json 2> /dev/null
vol.py -f $1 --profile=$2 --output=json malfind --output-file=$1-$2-malfind.json 2> /dev/null
vol.py -f $1 --profile=$2 --output=json netscan --output-file=$1-$2-netscan.json 2> /dev/null
vol.py -f $1 --profile=$2 --output=json cmdline --output-file=$1-$2-cmdline.json 2> /dev/null
vol.py -f $1 --profile=$2 --output=json connscan --output-file=$1-$2-connscan.json 2> /dev/null
read -e -p "Run apihooks? It may take quite a while. (y/n) " yesno
if [[ $yesno =~ [Yy] ]]; then
	vol.py -f $1 --profile=$2 --output=json apihooks --output-file=$1-$2-apihooks.json 2> /dev/null
else
	echo "skipping apihooks"
fi
volGraph.py $1-$2-*.json
echo "...done."
echo
