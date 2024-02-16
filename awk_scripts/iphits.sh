
#! /bin/sh

ipaddr=""

read -p "Enter IP Address:" ipaddr

echo $ipaddr

nstcpdump.sh -G 60 dst host $ipaddr > /var/tmp/$ipaddr.txt

awk '{print $3}' /var/tmp/$ipaddr.txt | awk -F '.' '{OFS="."} {print $1,$2,$3,$4}' | sort | uniq > /var/tmp/$ipaddruniq.txt

cat /var/tmp/$ipaddruniq.txt
