#!/usr/bin/env python3

# -*- coding: utf-8 -*-

import requests
import json
import sys
import argparse
import easysnmp

maintainer = "kainzjoh"

def main():
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
                if "5.2.0" in vulnerableconf:
                    retval1.append(cve["id"])
        except KeyError:
            print("Key not Found")
        try:
            for vulnerableconf2_2 in cve["vulnerable_configuration_cpe_2_2"]:
                if "5.2.0" in vulnerableconf:
                    retval2.append(cve["id"])
        except KeyError:
            print("Key not Found")
            sys.exit(3)
    if len(retval1) != 0 or len(retval2) != 0:
        print(retval1 + retval2)
        sys.exit(1)

if __name__ == '__main__':
    main()
