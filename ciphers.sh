#Usage ./ciphers.sh <server>:<port>
SERVER=$1
DELAY=1
ciphers=$(openssl ciphers 'ALL:eNULL' | sed -e 's/:/ /g')
echo Obtaining cipher list from $(openssl version).
for cipher in ${ciphers[@]}
do
echo -n Testing $cipher...
result=$(echo | openssl s_client -cipher "$cipher" -connect $SERVER 2>&1)
if [[ "$result" =~ ":error" ]] ; then
	error=$(echo -n $result | cut -d':' -f6)
	echo NO \($error\)
else
	if [[ "$result" =~ "Cipher is ${cipher}" || "$result" =~ "Cipher    :" ]] ; then
		echo YES
	else
		echo UNKNONW RESPONSE
		echo $result
	fi
fi
sleep $DELAY
done
