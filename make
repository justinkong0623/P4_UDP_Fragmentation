.PHONY:setup clean

setup: 
	sudo ifconfig vf0_0 192.168.1.151 netmask 255.255.255.0
	sudo arp -s 192.168.1.150 e4:1d:2d:19:66:20
	sudo ethtool -K vf0_0 rx off
	sudo ethtool -K vf0_0 tx off
	sudo ifconfig
clean:
