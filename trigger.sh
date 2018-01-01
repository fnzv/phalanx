#!/bin/bash


# Target hostname
hostname=`dig -x ${1} +short`

# Sending an Email Alert:
echo "Automated DDoS detection triggered this script" | mail -s "Anti-DDoS detection: IP $1" your-email@example.com

# Execute ban code here:

# ssh into Compute node and add an ipset or iptables rule to nullroute this IP for $2 timeout

# Open ticket/Abuse to xyz company for malicious traffic

# Send slack/mattermost/telegram notification


# Parameters coming from detectord.go script
#  $1 ip_address
#  $2 timeout
