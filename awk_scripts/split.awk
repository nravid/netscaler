BEGIN {
	print "IP split"
	  }
		
{
	OFS="."
}
{
	split($3,ip,"."); 
	print ip[1],ip[2],ip[3],ip[4];
}
