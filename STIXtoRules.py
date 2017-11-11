# Rule generator
# created by Lauren Rudman
# Takes a STIX IOC and generates Snort, IPFW, iptables and more

# python-stix
from stix.core import STIXPackage

# virus-total api
import simplejson
import urllib
import urllib2

samplehash = "4490f3fa2648806af107642474ffcfc9" #TODO
# Parse input file
stix_package = STIXPackage.from_xml('4490f3fa2648806af107642474ffcfc9.xml')

def main():
	# Convert STIXPackage to a Python dictionary via the to_dict() method.
	stix_dict = stix_package.to_dict()

	indicator_dict = stix_dict['indicators']
	
	# test
	createIPTABLES(indicator_dict)	
	createSNORT(indicator_dict)
	createIPFW(indicator_dict)
	getDNSQuery(indicator_dict)
	getHTTPRequest(indicator_dict)
	getUDPPacket(indicator_dict)
	getSSHPacket(indicator_dict)
	getFTPPacket(indicator_dict)
	
	
# ~~~~~~~~~~~~~~~~~~~~~~~~~ XML TO LISTS METHODS ~~~~~~~~~~~~~~~~~~~~~~~~~

def getURIs(indicator_dict):
	urilist = []
	for observable_dict in indicator_dict:
		if observable_dict['observable']['object']['properties']['xsi:type'] == 'URIObjectType':
			urilist.append(observable_dict['observable']['object']['properties']['value'])			
			print observable_dict['observable']['object']['properties']['value']	
	return urilist

def getDomains(indicator_dict):
	domainlist = []
	for observable_dict in indicator_dict:
		if observable_dict['observable']['object']['properties']['xsi:type'] == 'DomainNameObjectType':
			domainlist.append(observable_dict['observable']['object']['properties']['value'])			
			print observable_dict['observable']['object']['properties']['value']	
	return domainlist

def getIPAddress(indicator_dict):
	iplist = []
	for observable_dict in indicator_dict:
		if observable_dict['observable']['object']['properties']['xsi:type'] == 'AddressObjectType':
			iplist.append(observable_dict['observable']['object']['properties']['address_value'])			
			print observable_dict['observable']['object']['properties']['address_value']	
	return iplist


def getTCPSYN(indicator_dict): # done
	tcplist = []
	for observable_dict in indicator_dict:
		if observable_dict['observable']['object']['properties']['xsi:type'] == 'NetworkConnectionObjectType':
			if observable_dict['observable']['object']['properties']['layer4_protocol'] == 'TCP':
				try: # incoming
					source_port = observable_dict['observable']['object']['properties']['source_socket_address']['port']['port_value']
					source_address = observable_dict['observable']['object']['properties']['source_socket_address']['ip_address']['address_value']	
					if [source_port, source_address, "in"] not in tcplist:
						tcplist.append([source_port, source_address, "in"])			
				except: # outgoing
					destination_port = observable_dict['observable']['object']['properties']['destination_socket_address']['port']['port_value']
					destination_address = observable_dict['observable']['object']['properties']['destination_socket_address']['ip_address']['address_value']
					if [destination_port, destination_address, "out"] not in tcplist:
						tcplist.append([destination_port, destination_address, "out"])			
	print tcplist
	return tcplist

def getDNSQuery(indicator_dict):
	dnslist = []
	for observable_dict in indicator_dict:
		if observable_dict['observable']['object']['properties']['xsi:type'] == 'NetworkConnectionObjectType':
			try:
				if observable_dict['observable']['object']['properties']['layer7_protocol'] == "DNS":			
					print "DNS"
					destination_port = observable_dict['observable']['object']['properties']['destination_socket_address']['port']['port_value']
					uri = observable_dict['observable']['object']['properties']['layer7_connections']['dns_query']['question']['qname']['value']
					dnslist.append((uri,destination_port))
			except:
				pass
	return dnslist
	

def getHTTPRequest(indicator_dict):
	httplist = []
	for observable_dict in indicator_dict:		
		if observable_dict['observable']['object']['properties']['xsi:type'] == 'HTTPSessionObjectType':
			print observable_dict
			method = observable_dict['observable']['object']['properties']['http_request_response'][0]['http_client_request']['http_request_line']['http_method']
			uri = observable_dict['observable']['object']['properties']['http_request_response'][0]['http_client_request']['http_request_line']['value']
			version = observable_dict['observable']['object']['properties']['http_request_response'][0]['http_client_request']['http_request_line']['version']
			accept = observable_dict['observable']['object']['properties']['http_request_response'][0]['http_client_request']['http_request_header']['parsed_header']['accept']
			connection = observable_dict['observable']['object']['properties']['http_request_response'][0]['http_client_request']['http_request_header']['parsed_header']['connection']
			host = observable_dict['observable']['object']['properties']['http_request_response'][0]['http_client_request']['http_request_header']['parsed_header']['host']['domain_name']['value']
			port = observable_dict['observable']['object']['properties']['http_request_response'][0]['http_client_request']['http_request_header']['parsed_header']['host']['port']['port_value']
			httplist.append([method, uri, version, accept, connection, host, port])
			print "HTTP"
	return httplist

def getUDPPacket(indicator_dict):
	udplist = []
	for observable_dict in indicator_dict:
		if observable_dict['observable']['object']['properties']['xsi:type'] == 'NetworkConnectionObjectType':
			if observable_dict['observable']['object']['properties']['layer4_protocol'] == 'UDP':
				try:				 
					nope = observable_dict['observable']['object']['properties']['layer7_protocol']
				except:
					print "UDP"
					try: # incoming
						source_port = observable_dict['observable']['object']['properties']['source_socket_address']['port']['port_value']
						source_address = observable_dict['observable']['object']['properties']['source_socket_address']['ip_address']['address_value']
						if [source_address, source_port, "in"] not in udplist:
							udplist.append([source_port, source_address, "in"])
					except: # outgoing
						destination_address = observable_dict['observable']['object']['properties']['destination_socket_address']['ip_address']['address_value']
						destination_port = observable_dict['observable']['object']['properties']['destination_socket_address']['port']['port_value']
						if [destination_address, destination_port, "out"] not in udplist:
							udplist.append([destination_port, destination_address, "out"])
	print udplist	
	return udplist

def getSSHPacket(indicator_dict):
	sshlist = []
	for observable_dict in indicator_dict:
		if observable_dict['observable']['object']['properties']['xsi:type'] == 'NetworkConnectionObjectType':
			try:
				if observable_dict['observable']['object']['properties']['layer7_protocol'] == 'SSH':
					try: # incoming
						source_port = observable_dict['observable']['object']['properties']['source_socket_address']['port']['port_value']
						source_address = observable_dict['observable']['object']['properties']['source_socket_address']['ip_address']['address_value']	
						if [source_port, source_address, "in"] not in sshlist:
							sshlist.append([source_port, source_address, "in"])			
					except: # outgoing
						destination_port = observable_dict['observable']['object']['properties']['destination_socket_address']['port']['port_value']
						destination_address = observable_dict['observable']['object']['properties']['destination_socket_address']['ip_address']['address_value']
						if [destination_port, destination_address, "out"] not in sshlist:
							sshlist.append([destination_port, destination_address, "out"])	
			except:
				pass
	print sshlist
	return sshlist

def getFTPPacket(indicator_dict):
	ftplist = []
	for observable_dict in indicator_dict:
		if observable_dict['observable']['object']['properties']['xsi:type'] == 'NetworkConnectionObjectType':
			try:
				if observable_dict['observable']['object']['properties']['layer7_protocol'] == 'FTP':
					try: # incoming
						source_port = observable_dict['observable']['object']['properties']['source_socket_address']['port']['port_value']
						source_address = observable_dict['observable']['object']['properties']['source_socket_address']['ip_address']['address_value']	
						if [source_port, source_address, "in"] not in ftplist:
							ftplist.append([source_port, source_address, "in"])			
					except: # outgoing
						destination_port = observable_dict['observable']['object']['properties']['destination_socket_address']['port']['port_value']
						destination_address = observable_dict['observable']['object']['properties']['destination_socket_address']['ip_address']['address_value']
						if [destination_port, destination_address, "out"] not in ftplist:
							ftplist.append([destination_port, destination_address, "out"])	
			except:
				pass
	print ftplist
	return ftplist

def getICMPPacket(indicator_dict):
	icmplist = []
	for observable_dict in indicator_dict:
		if observable_dict['observable']['object']['properties']['xsi:type'] == 'NetworkConnectionObjectType':
			if observable_dict['observable']['object']['properties']['layer3_protocol'] == 'ICMP':
				try: # incoming					
					source_address = observable_dict['observable']['object']['properties']['source_socket_address']['ip_address']['address_value']
					type_field = observable_dict['description']	
					if [source_address, "in"] not in icmplist:
						icmplist.append([source_address, "in", type_field])			
				except: # outgoing					
					destination_address = observable_dict['observable']['object']['properties']['destination_socket_address']['ip_address']['address_value']
					type_field = observable_dict['description']
					if [destination_address, "out"] not in icmplist:
						icmplist.append([destination_address, "out", type_field])			
	print icmplist
	return icmplist

# ~~~~~~~~~~~~~~~~~~~~~~~~~ LIST TO RULE STRING METHODS ~~~~~~~~~~~~~~~~~~~~~~~~~

# ######### SNORT #########
def IPtoSNORT(iplist, sid):
	return "alert ip $HOME_NET any -> "+iplist+' any (msg:"Suspicious IP address seen"; logto:"RulesFromSTIX.log"; sid:'+str(sid)+';)\n'

# ?_port, ?_address, out/in
def TCPPortIPtoSNORT(portIP, sid, protocol):
	out = portIP[2] == "out"	
	return "alert TCP $HOME_NET any {0} {1} {2} (msg:\"Suspicious {3} {6} connection {4}\"; classtype:bad-unknown; sid:{5};)\n".format("->" if out else "<-", portIP[1], str(portIP[0]), "outgoing" if out else "incoming", samplehash, str(sid), protocol)

# ?_port, ?_address, out/in
def UDPPortIPtoSNORT(portIP, sid, protocol):
	out = portIP[2] == "out"	
	return "alert UDP $HOME_NET any {0} {1} {2} (msg:\"Suspicious {3} {6} connection {4}\"; classtype:bad-unknown; sid:{5};)\n".format("->" if out else "<-", portIP[1], str(portIP[0]), "outgoing" if out else "incoming", samplehash, str(sid), protocol)

# uri, destination_port
def DNStoSNORT(dnslist, sid):
	return "alert udp $HOME_NET any -> any {2} (msg:\"Suspicious domain name request {3}\"; content:\"{0}\"; classtype:bad-unknown; sid:{1};)\n".format(dnslist[0], sid, dnslist[1], samplehash)

def ICMPtoSNORT(icmplist, sid):
	out = icmplist[1] == "out"	
	return "alert ICMP $HOME_NET any {0} {1} any (msg:\"Suspicious {2} {5} connection {3}\"; classtype:bad-unknown; sid:{4};)\n".format("->" if out else "<-", icmplist[1], "outgoing" if out else "incoming", samplehash, str(sid),"ICMP")	

# method, uri, version, accept, connection, host, port
def HTTPReqtoSNORT(httplist, sid):
	return "alert tcp $HOME_NET any -> any {0} (msg:\"Malicious {1} detected {2}\"; content:\"{5}\"; http_header; content:\"{3}\"; http_uri; nocase; sid:{4};)\n".format(httplist[6], "HTTP "+httplist[0]+" request", samplehash, httplist[1], sid, httplist[5])

# ######### iptables #########
def TCPtoiptables(tcplist):
	out = tcplist[2] == "out"
	if out:
		return 'iptables -A OUTPUT -j DROP -p tcp --syn {0} {1} {2} {3} \n'.format("--dport" if out else "--sport", tcplist[0], "-d" if out else "-s", tcplist[1])
	else:
		return 'iptables -A INPUT -j DROP -p tcp --syn {0} {1} {2} {3} \n'.format("--dport" if out else "--sport", tcplist[0], "-d" if out else "-s", tcplist[1])
	# destination_port, destination_address, "out"
def HTTPReqtoiptables(httplist):
	return 'iptables -A OUTPUT -j DROP -p tcp --dport {0} -m string --algo bm --string "{1}" LOG --log-prefix "Suspicious HTTP requests"\n'.format(httplist[6], httplist[5]+httplist[1])
	#method, uri, version, accept, connection, host, port
def UDPtoiptables(udplist):
	out = udplist[2] == "out"
	if out:
		return 'iptables -A OUTPUT -j DROP -p udp {0} {1} {2} {3} \n'.format("--dport" if out else "--sport", udplist[0], "-d" if out else "-s", udplist[1])
	else:
		return 'iptables -A INPUT -j DROP -p udp {0} {1} {2} {3} \n'.format("--dport" if out else "--sport", udplist[0], "-d" if out else "-s", udplist[1])
	# destination_port, destination_address, "out"
def DNStoiptables(dnslist):
	return 'iptables -A OUTPUT -j DROP -p udp --dport {0} -m string --algo bm --string "{1}" LOG --log-prefix "Suspicious DNS requests"\n'.format(dnslist[1], dnslist[0])
	# uri, destination_port
def ICMPtoiptables(icmplist):
	out = icmplist[2] == "out"
	if out:
		if icmplist[2] == "8":
			return 'iptables -A OUTPUT -j DROP -p icmp --icmp-type {2} {0} {1} \n'.format("-d" if out else "-s", icmplist[1], icmplist[2])
		else:
			return 'iptables -A OUTPUT -j DROP -p icmp --icmp-type {2} {0} {1} \n'.format("-d" if out else "-s", icmplist[1], icmplist[2])
	else:
		if icmplist[2] == "8":
			return 'iptables -A INPUT -j DROP -p icmp --icmp-type {2} {0} {1} \n'.format("-d" if out else "-s", icmplist[1], icmplist[2])
		else:
			return 'iptables -A INPUT -j DROP -p icmp --icmp-type {2} {0} {1} \n'.format("-d" if out else "-s", icmplist[1], icmplist[2])
	# source_address, "in", type_field

# ######### IPFW #########
def TCPPortIPtoIPFW(tcplist, rule_number, set_number):
	out = tcplist[2] == "out"
	if out:
		return "add {0} {1} reject tcp from any any to {2} {3}\n".format(rule_number, set_number, tcplist[1], tcplist[0])
	else:
		return "add {0} {1} reject tcp from {2} {3} to any any\n".format(rule_number, set_number, tcplist[1], tcplist[0])

def UDPPortIPtoIPFW(udplist, rule_number, set_number):
	out = udplist[2] == "out"
	if out:
		return "add {0} {1} reject udp from any any to {2} {3}\n".format(rule_number, set_number, udplist[1], udplist[0])
	else:
		return "add {0} {1} reject udp from {2} {3} to any any\n".format(rule_number, set_number, udplist[1], udplist[0])

def ICMPtoIPFW(icmplist, rule_number, set_number):
	out = icmplist[1] == "out"
	if out:
		return "add {0} {1} deny icmp from any to {2} \n".format(rule_number, set_number, icmplist[0])
	else:
		return "add {0} {1} deny icmp from {2} to any \n".format(rule_number, set_number, icmplist[0])


# ~~~~~~~~~~~~~~~~~~~~~~~~~ CREATE RULES METHODS ~~~~~~~~~~~~~~~~~~~~~~~~~

def createSNORT(indicator_dict):
	# rule actions - alert, log, drop, reject
	# action protocol ip port -> ip port 
	snortrules_file = open('SNORTRules.txt','w')
	sid = 234500
	# tcp syn rules	
	tcplist = getTCPSYN(indicator_dict)	
	for tcp_tuple in tcplist:
		snortrules_file.write(TCPPortIPtoSNORT(tcp_tuple, sid, "TCP"))
	# ssh connection rules
	sshlist = getSSHPacket(indicator_dict)
	for ssh in sshlist:
		snortrules_file.write(TCPPortIPtoSNORT(ssh, sid, "SSH"))
	# ftp conenction rules
	ftplist = getFTPPacket(indicator_dict)
	for ftp in ftplist:
		snortrules_file.write(TCPPortIPtoSNORT(ftp, sid, "FTP"))
	# udp conenction rules
	udplist = getUDPPacket(indicator_dict)
	for udp in udplist:
		snortrules_file.write(UDPPortIPtoSNORT(udp, sid, "UDP"))
	# domain name rules
	domainlist = getDNSQuery(indicator_dict)
	for domain in domainlist:
		snortrules_file.write(DNStoSNORT(domain, sid))
	# http GET/POST request
	httplist = getHTTPRequest(indicator_dict)
	for http in httplist:
		snortrules_file.write(HTTPReqtoSNORT(http, sid))
	# icmp connection rules
	icmplist = getICMPPacket(indicator_dict)
	for icmp in icmplist:
		snortrules_file.write(ICMPtoSNORT(icmp, sid))
	snortrules_file.close()

def createIPFW(indicator_dict):
	rule_number = 1000
	set_number = 30
	ipfwrules_file = open('IPFWRules.txt','w')
	# tcp based rules
	tcplist = getTCPSYN(indicator_dict)	
	for tcp_tuple in tcplist:
		ipfwrules_file.write(TCPPortIPtoIPFW(tcp_tuple, rule_number, set_number))
	# ssh connection rules
	sshlist = getSSHPacket(indicator_dict)
	for ssh in sshlist:
		ipfwrules_file.write(TCPPortIPtoIPFW(ssh, rule_number, set_number))
	# ftp conenction rules
	ftplist = getFTPPacket(indicator_dict)
	for ftp in ftplist:
		ipfwrules_file.write(TCPPortIPtoIPFW(ftp, rule_number, set_number))
	# udp conenction rules
	udplist = getUDPPacket(indicator_dict)
	for udp in udplist:
		ipfwrules_file.write(UDPPortIPtoIPFW(udp, rule_number, set_number))
	# icmp connection rules
	icmplist = getICMPPacket(indicator_dict)
	for icmp in icmplist:
		ipfwrules_file.write(ICMPtoIPFW(icmp, rule_number, set_number))
	ipfwrules_file.close()

def createIPTABLES(indicator_dict):
	# http://ipset.netfilter.org/iptables.man.html
	# http://ipset.netfilter.org/iptables-extensions.man.html
	# accept (let packet through), drop (drop packet), queue (pass packet to userspace?), return (stop traversing this chain and resume at the next rule)
	# -A (append to a chain (INPUT, OUTPUT, FORWARD)), -C (check if the rule exists in a chain)
	# -p (tcp, udp, udplite, icmp, esp, ah, sctp, all), -s (source IP, networkname, hostname, network IP with mask), -d (destination IP, networkname, hostname, network IP with mask), 
	# -m (match), -j (specify what happends when the packet matches), --string (matches the given pattern) 
	
	iptablesRules = open('IPTablesRules','w')
	# TODO
	# tcp syn rules
	tcplist = getTCPSYN(indicator_dict)	
	for tcp_tuple in tcplist:
		iptablesRules.write(TCPtoiptables(tcp_tuple))
	# ssh connection rules
	sshlist = getSSHPacket(indicator_dict)
	for ssh in sshlist:
		iptablesRules.write(TCPtoiptables(ssh))
	# ftp conenction rules
	ftplist = getFTPPacket(indicator_dict)
	for ftp in ftplist:
		iptablesRules.write(TCPtoiptables(ftp))
	# domain name rules
	domainlist = getDNSQuery(indicator_dict)
	for domain in domainlist:
		iptablesRules.write(DNStoiptables(domain))
	# http GET/POST request
	httplist = getHTTPRequest(indicator_dict)
	for http in httplist:
		iptablesRules.write(HTTPReqtoiptables(http))
	
	# udp conenction rules
	udplist = getUDPPacket(indicator_dict)
	for udp in udplist:
		iptablesRules.write(UDPtoiptables(udp))
	# icmp connection rules
	icmplist = getICMPPacket(indicator_dict)
	for icmp in icmplist:
		iptablesRules.write(ICMPtoiptables(icmp))
	iptablesRules.close()	


# ~~~~~~~~~~~~~~~~~~~~~~~~~ UTILITY METHODS ~~~~~~~~~~~~~~~~~~~~~~~~~

def IPAddressStringMaker(iplist):
	print 'iplist', iplist
	ip_string = ""
	for ip in range(0, len(iplist)-2):
			ip_string = ip_string+iplist[ip]+" or "
			print "ip: ", ip
	ip_string = ip_string+iplist[ip-1]
	return ip_string

def checkReputation(uri):
	url = "https://www.virustotal.com/vtapi/v2/url/scan"
	parameters = {"url": uri, "apikey": "6297278ce14f21b1b77ecef1014fe2023d80ac7919d1477445a83c2614f345dc"}			
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)	
	print response.read()

if __name__ == '__main__':
    main()
