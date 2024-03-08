
#!/bin/sh

#awk '/default BOT Message/ {print$18} END {print q}' /var/log/ns.log | sort | uniq > /var/tmp/bothitsuniq.txt

#awk '/bind policy patset pat/ {print $5} END {print q}' /nsconfig/ns.conf | sort > /var/tmp/bindpat.txt

#diff -y /var/tmp/bothitsuniq.txt /var/tmp/bindpat.txt | grep '<'


diff -y <(awk '/default BOT Message/ {print$18} END {print q}' /var/log/ns.log | sort -u) <(awk '/bind policy patset pat/ {print $5} END {print q}' /nsconfig/ns.conf | sort) | grep '<'
