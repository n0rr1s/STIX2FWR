# Rule generator
# created by Lauren Rudman
# Takes a STIX IOC and generates Snort, IPFW, iptables and more

# python-stix
from stix.core import STIXPackage

def main():

	# Parse input file
	stix_package = STIXPackage.from_xml('IOCStix.xml')

	# Convert STIXPackage to a Python dictionary via the to_dict() method.
	stix_dict = stix_package.to_dict()

	indicator_dict = stix_dict['indicators']
	
	# test
	createIPFW(indicator_dict)	
	
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

def getTCPSYN(indicator_dict):
	tcplist = []
	for observable_dict in indicator_dict:
		if observable_dict['observable']['object']['properties']['xsi:type'] == 'NetworkConnectionObjectType':
			tcplist.append((observable_dict['observable']['object']['properties']['source_socket_address']['port']['port_value'],observable_dict['observable']['object']['properties']['destination_socket_address']['port']['port_value'],observable_dict['observable']['object']['properties']['destination_socket_address']['ip_address']['address_value']))			
	print tcplist
	return tcplist

# ~~~~~~~~~~~~~~~~~~~~~~~~~ CREATE RULES METHODS ~~~~~~~~~~~~~~~~~~~~~~~~~

def createSNORT(indicator_dict):
	urilist = getURIs(indicator_dict)
	domainlist = getDomains(indicator_dict)	
	iplist = getIPAddress(indicator_dict)
	tcplist = getTCPSYN(indicator_dict)

def createIPFW(indicator_dict):
	rule_number = 0
	set_number = 30
	ipfwrules_file = open('IPFWRules.txt','w')
	# ip address rules
	iplist = getIPAddress(indicator_dict)	
	ipfwrules_file.write(str(rule_number)+" "+str(set_number)+" deny ip from any to {"+IPAddressStringMaker(iplist)+"}")
	ipfwrules_file.write("\n")
	# tcp syn rules
	tcplist = getTCPSYN(indicator_dict)
	for tcp_tuple in tcplist:
		ipfwrules_file.write(str(rule_number)+" "+str(set_number)+" deny ip from any "+str(tcp_tuple[0])+" to "+tcp_tuple[2]+" "+str(tcp_tuple[1]))
		ipfwrules_file.write("\n")
	ipfwrules_file.close()

def createIPTABLES(indicator_dict):
	urilist = getURIs(indicator_dict)
	domainlist = getDomains(indicator_dict)	
	iplist = getIPAddress(indicator_dict)
	tcplist = getTCPSYN(indicator_dict)

# ~~~~~~~~~~~~~~~~~~~~~~~~~ UTILITY METHODS ~~~~~~~~~~~~~~~~~~~~~~~~~

def IPAddressStringMaker(iplist):
	ip_string = ""
	for ip in range(0, len(iplist)-2):
			ip_string = ip_string+iplist[ip]+" or "
	ip_string = ip_string+iplist[ip-1]
	return ip_string	


if __name__ == '__main__':
    main()
