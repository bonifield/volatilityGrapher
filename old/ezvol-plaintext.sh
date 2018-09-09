#!/bin/bash
# v1.0 - to assist with volCombine.py v1.3.4
# note this script uses "volatility" vs "vol.py"

if [ $# -eq 0 ]; then
	echo "Usage:  ezvol.sh your-memory-dump.dmp"
	exit 1
else
	if [ $(which volatility | wc -l) -gt 0 ]; then
		fileName=$1
	else
		echo "volatility not present or not in your system path (do you have vol.py instead of volatility?)"
		exit 2
fi

echo -e "\n---==== ezvol ====---"

echo -ne "running imageinfo\r"

ii="$fileName-imageinfo.txt"
volatility -f $fileName imageinfo > $ii 2> /dev/null
prof=`grep 'Profile' $ii | sed -e 's/ \+//g' | cut -d ':' -f2 | cut -d ',' -f1`

pl="$fileName-$prof-pslist.txt"
ps="$fileName-$prof-psscan.txt"
mf="$fileName-$prof-malfind.txt"
en="$fileName-$prof-envars.txt"
cn="$fileName-$prof-connections.txt"
cs="$fileName-$prof-connscan.txt"
ss="$fileName-$prof-sockets.txt"
so="$fileName-$prof-sockscan.txt"
ns="$fileName-$prof-netscan.txt"

echo -ne "found best profile: $prof\r\n"
echo -ne "running pslist    \r"
volatility -f $fileName --profile=$prof pslist > $pl  2> /dev/null
echo -ne "running psscan    \r"
volatility -f $fileName --profile=$prof psscan > $ps  2> /dev/null
echo -ne "running malfind    \r"
volatility -f $fileName --profile=$prof malfind > $mf  2> /dev/null
echo -ne "running envars    \r"
volatility -f $fileName --profile=$prof envars > $en  2> /dev/null

if [[ $prof =~ "WinXP" || $prof =~ "Win2003" ]]; then
	echo -ne "running connections   \r"
	volatility -f $fileName --profile=$prof connections > $cn  2> /dev/null
	echo -ne "running connscan      \r"
	volatility -f $fileName --profile=$prof connscan > $cs  2> /dev/null
	echo -ne "running sockets       \r"
	volatility -f $fileName --profile=$prof sockets > $ss  2> /dev/null
	echo -ne "running sockscan      \r"
	volatility -f $fileName --profile=$prof sockscan > $so  2> /dev/null
elif [[ $prof =~ "Win7" || $prof =~ "Win2008" || $prof =~ "Win2012" ]]
	echo -ne "running netscan       \r"
	volatility -f $fileName --profile=$prof netscan > $ns  2> /dev/null
fi

echo -ne "done                  \r\n"
ls $fileName*.txt
echo

if [ $(which dot | wc -l) -gt 0 ]; then
	if [ $(which volCombine.py | wc -l) -gt 0 ]; then
		python volCombine.py $pl $ps $mf $en
	else
		echo "did not find volCombine.py in the system path...  may need to type: export PATH=\$PATH:/your/volCombine/folder/"
		echo
		exit 3
	fi
else
	echo "did not find dot (part of graphviz)"
	exit 4
fi

exit 0
