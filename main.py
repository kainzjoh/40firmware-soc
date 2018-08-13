#!/usr/bin/env python3

# -*- coding: utf-8 -*-

import requests
import json
import sys
import argparse
from easysnmp import Session

def main():
    # ./main.py -c abc123123 -p 161 -v 2 firewall01.corp.company.com
    parser = argparse.ArgumentParser()
    parser.add_argument("Hostname")
    parser.add_argument("-v","--version", type=int, choices=[1, 2], help="Version 1 or 2", default=2)
    parser.add_argument("-p","--port", type=int, help="Specify port to use", default=161)
    parser.add_argument("-c","--community", help="Specify Community to use", default="public")
    args = parser.parse_args()

    #print("DEBUG: " + args.Hostname, args.version, args.port, args.community)
    #sys.exit(0)
    try:
        ss = Session(hostname=args.Hostname, community=args.community, version=args.version)
        firmware = ss.get('1.3.6.1.4.1.12356.101.4.1.1.0').value[1:7]
        firmware = firmware if firmware[5] != "," else firmware[0:5] # chop trailing "," if minor Version <9
    except Exception as e:
        print("ERROR: ", end="")
        print(e)
        sys.exit(3)

    url = "http://cve.circl.lu/api/search/fortinet/fortios"
    try:
        response = requests.get(url)
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(3)
        
    r = json.loads(response.text)
    retval1 = []
    retval2 = []  
    for cve in r:
        try:
            for vulnerableconf in cve["vulnerable_configuration"]:
                if firmware in vulnerableconf:
                    retval1.append(cve["id"])
        except KeyError:
            print("Key not Found")
        try:
            for vulnerableconf2_2 in cve["vulnerable_configuration_cpe_2_2"]:
                if firmware in vulnerableconf:
                    retval2.append(cve["id"])
        except KeyError:
            print("Key not Found")
            sys.exit(3)
    if len(retval1) != 0 or len(retval2) != 0:
        print("CRITICAL: Vulnerabilities found for " + (firmware) , end=" ")
        print(retval1 + retval2)
        sys.exit(2)
    else:
        print("OK: No vulnerability found for " + firmware)
        sys.exit(0)

if __name__ == '__main__':
    main()
