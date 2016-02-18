# Rule generator
# created by Lauren Rudman
# Takes a STIX IOC and generates Snort, IPFW, iptables and more

# python-stix
from stix.core import STIXPackage

# virus-total api
import simplejson
import urllib
import urllib2

def main():

	# Parse input file
	stix_package = STIXPackage.from_xml('IOCStix.xml')

	# Convert STIXPackage to a Python dictionary via the to_dict() method.
	stix_dict = stix_package.to_dict()

	indicator_dict = stix_dict['indicators']
	
	# test
	createSNORT(indicator_dict)	
	
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
	# rule actions - alert, log, drop, reject
	# action protocol ip port -> ip port 
	snortrules_file = open('SNORTRules.txt','w')
	sid = 234500
	# uri rules
	#for i in urilist:
	#	checkReputation(i)
	urilist = getURIs(indicator_dict)
	for uri in urilist:
		snortrules_file.write('alert tcp $HOME_NET any -> any 80 (msg:"Malicious HTTP GET request"; content:"'+uri+'"; http_uri; nocase; sid:'+str(sid)+';)')
		sid = sid + 1
		snortrules_file.write("\n")
	# domain name rules
	domainlist = getDomains(indicator_dict)
	for domain in domainlist:
		snortrules_file.write('alert udp $HOME_NET any -> any 53 (msg:"Suspicious domain name request"; content:"'+domain+'"; sid:'+str(sid)+';)')
		snortrules_file.write("\n")
	iplist = getIPAddress(indicator_dict)
	# ip address rules
	for ip in iplist:
		snortrules_file.write("alert ip $HOME_NET any -> "+ip+' any (msg:"Suspicious IP address seen"; logto:"RulesFromSTIX.log"; sid:'+str(sid)+';)')
		snortrules_file.write("\n")
	tcplist = getTCPSYN(indicator_dict)
	#tcp syn rules
	for tcp_tuple in tcplist:
		snortrules_file.write("alert tcp $HOME_NET "+str(tcp_tuple[0])+" -> "+tcp_tuple[2]+" "+str(tcp_tuple[1])+' (msg:"Suspicious TCP connection"; classtype:tcp-connection; sid:'+str(sid)+';)')
		snortrules_file.write("\n")

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

def checkReputation(uri):
	url = "https://www.virustotal.com/vtapi/v2/url/scan"
	parameters = {"url": uri, "apikey": "6297278ce14f21b1b77ecef1014fe2023d80ac7919d1477445a83c2614f345dc"}			
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)	
	print response.read()

if __name__ == '__main__':
    main()
