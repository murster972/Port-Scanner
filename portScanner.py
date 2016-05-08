#simple port scanner
#gets the host and ports
#then goes through each port trying to connect
#if succesful then the port is open
#if not the port is closed

import os
from socket import *

def main():
	os.system("clear")
	targetHost = raw_input("Hosts (seperate with spaces): ")
	targetPorts = raw_input("ports (seperate with spaces): ")
	targetPorts = targetPorts.split()
	targetHost = targetHost.split()

	if len(targetHost) == 0 or len(targetPorts) == 0:
		print "Please enter a valid host and port to use."
		pause = raw_input()
		main()

	else:
		portScan(targetHost, targetPorts)

def connectScan(tgtHost, tgtPort):
	try:
		conSocket = socket(AF_INET, SOCK_STREAM)
		conSocket.connect((tgtHost, tgtPort))
		conSocket.send("test...")
		received = conSocket.recv(100)
		print "[+] %d TCP open" % tgtPort
		print received

	except:
		print "[-] %d TCP closed" % tgtPort

def portScan(tgtHost, tgtPorts):
	os.system("clear")
	i = 0

	while i <= len(tgtHost):
		if i == len(tgtHost):
			pause = raw_input("\nPress enter to continue...")
			main()

		else:
			try:
				tgtIP = gethostbyname(tgtHost[i])

			except:
				print "[-] Cannot connect to %s; unknown host" % tgtHost[i]
				return

			try:
				tgtName = gethostbyaddr(tgtIP)
				print "[*] Scan results for: " + tgtName[0]

			except:
				print "[*] Scan results for: " + tgtIP

			setdefaulttimeout(1)

			for tgtPort in tgtPorts:
				print "[*]Scanning Port: %d" % int(tgtPort)
				connectScan(tgtHost[i], int(tgtPort))

			i += 1

main()