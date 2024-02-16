BEGIN {
	print "IP Count"
	  }
		
{
	ip[$3] ++
}
END {
	for (i in ip)
	print i, " accessed ", ip[i], " times"
	}