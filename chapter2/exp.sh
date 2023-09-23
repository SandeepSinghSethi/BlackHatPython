#!/bin/bash
echo $# $@

if [[ $# -lt 1 ]] ; then  
	echo "Give the ip or domain name"
	exit 1
fi

echo "Getting ASN info about $1" #| notify -silent
asnmap -d $1 -silent | tee asninfo.txt | notify -silent 1>/dev/null

echo "Getting live hosts" | notify -silent
touch livehosts.txt
for i in $(cat asninfo.txt); do
	for j in $(prips $i); do
		httpx -u $j -silent | notify -silent | tee -a livehosts.txt 1>/dev/null
	done
done

for i in $(cat livehosts.txt); do
	cdncheck -i $j -silent | notify -silent 1>/dev/null
done

echo "Getting info about waf used or not " | notify -silent
touch allipcdn.txt
cdncheck -i $1 -silent | notify -silent 1>/dev/null
for i in $(cat livehosts.txt);do
	cdncheck -i $i | tee -a allipcdn.txt | notify -silent 1>/dev/null
done

echo "Getting Waybackurls into a file" | notify -silent
waybackurls $1 | tee waybackurl.txt  1>/dev/null

echo "Getting subdomains " | notify -silent
subfinder -d $1 -silent -o subs.txt | notify -silent 1>/dev/null

echo "Getting unique values" | notify -silent
cat waybackurl.txt subs.txt | anew sorted.txt 1>/dev/null

##echo "Running nmap on $1" | notify -silent
##nmap -sS -sV -Pn -A $1 -v -T5 | tee nmap.txt | notify -silent
#
echo "Using naabu also " | notify -silent
naabu -host $1 -o naabu.txt | notify -silent 1>/dev/null
touch allipnaabu.txt
for i in $(cat livehosts.txt);do
	naabu -host $i | tee -a allipnaabu.txt | notify -silent 1>/dev/null
done

echo "Checking for broken images " 
socialhunter -f livehosts.txt | notify -silent 

##echo "Checking for subdomain takeover"
#
#
#
#
