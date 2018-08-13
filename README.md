# 40Firmware-SOC
Check a given FortiGate for it's Firmware Version and for
Vulnerabilities using `http://cve.circl.lu/api/search/fortinet/fortios`

## Requirements
* Python3
* requests [Read the Docs](https://readthedocs.org/projects/requests/)
* easysnmp [Read the Docs](https://easysnmp.readthedocs.io/en/latest/)

## How does it work?
You have to at least specify a Hostname to connect to via snmp
the Script uses `OID:1.3.6.1.4.1.12356.101.4.1.1.0` to get the Firmware Version
and query the api for potential vulnerabilities

    usage: main.py [-h] [-host HOSTNAME] [-v {1,2}] [-p PORT] [-c COMMUNITY]
        
        optional arguments:
        -h, --help            show this help message and exit
        -host       HOSTNAME, --hostname HOSTNAME
        -v {1,2}, --version {1,2}
        -p PORT, --port PORT  Specify port to use
        -c COMMUNITY, --community COMMUNITY

