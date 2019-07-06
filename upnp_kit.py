# execute ssdp_scan.py to find upnp root
import urllib
import requests
from urllib.request import urlopen
from xml.dom import minidom
import time
import random
import netifaces
from netaddr import IPAddress
from scapy.all import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-s','--scan',help='discover upnp devices', action='store_true')
parser.add_argument('-u','--url',help='request control and scpd',type=str)
args = parser.parse_args()
location = args.url
interface = interface = netifaces.gateways()['default'][netifaces.AF_INET][1]

def get_network_addr():
    itype = netifaces.ifaddresses(netifaces.gateways()['default'][netifaces.AF_INET][1])[netifaces.AF_INET]
    current_netmask = itype[0]['netmask']
    network_address = IPAddress(current_netmask).netmask_bits()
    current_ip = itype[0]['addr']
    return str(current_ip) + "/" + str(network_address)

# create scan funtion to find out who runs upnp in the network
def ssdp_scan(interface):
# arp request    
    ans, unans = scapy.layers.l2.arping(get_network_addr(), iface=interface, timeout=5, verbose=False)
    for i, line in ans.res:
        ip_addr = line.sprintf("%ARP.psrc%")
# msearch request to discover upnp hosts    
        req = 'M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMan:"ssdp:discover"\r\nMX:3\r\n\r\n'
# send the message to the hosts        
        ip = IP(dst=ip_addr)
        udp = UDP(sport=random.randint(49152,65536),dport=1900)
        pkt = ip/udp/req
        try:
            start = time.time()
            rep = sr1(pkt,verbose=0,timeout=5)
            if rep[Raw]:
                results = rep[Raw].load
                print(ip_addr,results)
            else:
                pass
        except Exception as msg:
            print(msg)

# create function to convert xml to text
def xml_get_node_text(node):
    text = []
    for child_node in node.childNodes:
        if child_node.nodeType == node.TEXT_NODE:
            text.append(child_node.data)
    return(''.join(text))

def get_urls(location):
# location of upnp_root
    response = urlopen(location)
# parse the string
    root_xml = minidom.parseString(response.read())
# close the request
    response.close()
#  get urlbase
    base_url_elem = root_xml.getElementsByTagName('URLBase')
    #print(base_url_elem)
# check if it is only a base url
    if base_url_elem:
        base_url = xml_get_node_text(base_url_elem[0]).rstrip('/')
    else:
        url = urllib.parse.urlparse(location)
        base_url = '%s://%s' % (url.scheme, url.netloc)
        print(base_url)
    #print(root_xml.getElementsByTagName('service'))
    for node in root_xml.getElementsByTagName('service'):
        service_type = xml_get_node_text(node.getElementsByTagName('serviceType')[0])
        #print(root_xml.getElementsByTagName('service'))
# get the rest
        control_url = '%s/%s' % (
                base_url,
                xml_get_node_text(node.getElementsByTagName('controlURL')[0]))
        scpd_url = '%s%s' % (
                base_url,
                xml_get_node_text(node.getElementsByTagName('SCPDURL')[0]))
    
        #print(control_url,scpd_url,service_type)
        return {'service_type':service_type,'scpd':scpd_url,'control':control_url}
        #print('%s:\n SCPD_URL: %s\n CONTROL_URL: %s\n' % (service_type,scpd_url,control_url))

def get_actions():
    urls = get_urls(location)
    #actions = 
    print(urls)
#get_actions()

if args.url:
    get_urls(location)
    get_actions()
if args.scan:
    ssdp_scan(interface)
