
#!/bin/sh

ipaddr=$1

if [ "$#" -ne 1 ];
then
	echo "This script requires an IP Address."
	read -p "Enter IP Address:" ipaddr
fi

echo $ipaddr

nstcpdump.sh -G 60 dst host $ipaddr > /var/tmp/$ipaddr.txt

awk '{print $3}' /var/tmp/$ipaddr.txt | awk -F '.' '{OFS="."} {print $1,$2,$3,$4}' | sort -u > /var/tmp/$ipaddruniq.txt

cat /var/tmp/$ipaddruniq.txt
