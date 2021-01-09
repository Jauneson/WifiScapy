airmon-ng stop wlp2s0mon
ifconfig wlp2s0 down
iwconfig wlp2s0 mode managed
ifconfig wlp2s0 up
service networking restart
service network-manager restart

echo "done restart network"
