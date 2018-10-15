#!/bin/bash

echo
echo "Usage:  ezvol.sh somefile.dmp profile"
echo "Running.  This may take a minute..."
vol.py -f $1 --profile=$2 --output=json pslist --output-file=$1-$2-pslist.json 2> /dev/null && \
vol.py -f $1 --profile=$2 --output=json psscan --output-file=$1-$2-psscan.json 2> /dev/null && \
vol.py -f $1 --profile=$2 --output=json envars --output-file=$1-$2-envars.json 2> /dev/null && \
vol.py -f $1 --profile=$2 --output=json malfind --output-file=$1-$2-malfind.json 2> /dev/null && \
vol.py -f $1 --profile=$2 --output=json netscan --output-file=$1-$2-netscan.json 2> /dev/null && \
vol.py -f $1 --profile=$2 --output=json cmdline --output-file=$1-$2-cmdline.json 2> /dev/null && \
volGraph.py $1-$2-pslist.json $1-$2-psscan.json $1-$2-envars.json $1-$2-malfind.json $1-$2-netscan.json $1-$2-cmdline.json
echo "...done."
echo
