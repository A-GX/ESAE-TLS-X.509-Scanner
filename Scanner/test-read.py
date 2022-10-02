#################################################
#                libraries import               #
#################################################
### Public Libraries
import sys
from os.path import exists # check if file exists
from ipaddress import ip_address, ip_network # to check if ip in network
import socket # to convert all host name into ip addresses
from pprint import pprint
from threading import Thread
### Project defined
import LOG as LOG


if __name__ == "__main__":
   b_list = open("/home/antoine/Documenti/Education/Master2/TLS-X.509-Scanner/Scanner/test-input-files/week3-blocklist.txt", "r")
   in_list = open("/home/antoine/Documenti/Education/Master2/TLS-X.509-Scanner/Scanner/test-input-files/week3-input_testing.csv","r")
   b = extract(b_list)
   i = extract(in_list, True)
   print(set_to_scan(b,i)[0:9])