#!/bin/bash

#
# pcap-hunter
# by es0
#
#
# Description: Reads in pcap file and hunts for c2 connections using bash, zeek/bro, tshark, etc...
#
#

echo " ######   #####     #    ######        #     #                                   ";
echo " #     # #     #   # #   #     #       #     # #    # #    # ##### ###### #####  ";
echo " #     # #        #   #  #     #       #     # #    # ##   #   #   #      #    # ";
echo " ######  #       #     # ######  ##### ####### #    # # #  #   #   #####  #    # ";
echo " #       #       ####### #             #     # #    # #  # #   #   #      #####  ";
echo " #       #     # #     # #             #     # #    # #   ##   #   #      #   #  ";
echo " #        #####  #     # #             #     #  ####  #    #   #   ###### #    # ";
echo "                                                                                 ";
echo "                                                                                 ";
echo "                                                                                 ";
echo "                                                                                 ";
echo "                                                                                 ";
echo "                                                                         by: es0 ";
echo "                                                                                 ";
echo "                                                                                 ";
echo "                                                                                 ";


PCAP="$1"
if [ -z "$PCAP" ] 
then
	echo "USAGE: ./pcap-hunt.sh <PCAP-FILE>"
 
else
	echo "READING $PCAP"
	echo ""
	echo "PCAP INFO: "
	#tcpdump -tttt -n -r $PCAP | awk 'NR==1; END {print}'
	capinfos -a -e $PCAP
	echo ""
	echo ""
	sleep 3
	echo "****** Converting pcap with zeek ******"	
	echo ""
	bro -Cr $PCAP
	echo -e ""
	echo -e ""
	sleep 5

	echo -e "\e[33m*****************************"
	echo -e "\e[33m****** Hunting Beacons ******"
	echo -e "\e[33m*****************************"
	echo -e ""
	echo -e " \e[31m[+] \e[36mHunt for longest unique COnnections" 
	echo -e "\e[39mOutput: "
	cat conn.*log | bro-cut id.orig_h id.resp_h duration | sort -k 3 -rn | head
	echo -e " "
	echo -e " "
	echo -e " \e[31m[+] \e[36mHunt for Longest talk times"
	echo -e "\e[39mOutput:"
	cat conn.*log | bro-cut id.orig_h id.resp_h duration | sort | grep -v -e '^$' | grep -v '-' | datamash -g 1,2 sum 3 | sort -k 3 -rn | head
 	echo -e " "
	echo -e " "
	echo -e " \e[31m[+] \e[36mHunting for most connections"
	echo -e "\e[39mOutput:"
	cat conn*.log | bro-cut id.orig_h id.resp_h | sort | uniq -c | sort -rn | head
	echo -e " "
	echo -e " "
	
	sleep 5
	echo -e "\e[33m*********************************"
	echo -e "\e[33m****** Hunting c2 over DNS ******"
	echo -e "\e[33m*********************************"
	echo -e " "
	echo -e "\e[39mOutput: "
	# tshark -r $PCAP -T fields -e dns.qry.name | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -rn | head
	cat dns*.log | bro-cut query | sort | uniq | rev | cut -d . -f 1-2 | rev | sort | uniq -c | sort -rn | head
 
	echo " "
	echo " "
fi	
