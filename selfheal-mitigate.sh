#!/bin/bash
IP=$1
if [ -z "$IP" ]; then
  echo "Error: No IP provided"
  exit 1
fi
sudo /sbin/iptables -A INPUT -s "$IP" -j DROP 2> ~/iptables_error.log
if [ $? -ne 0 ]; then
  echo "iptables failed, check ~/iptables_error.log"
fi
sudo service ssh restart
echo "Blocked IP: $IP"
