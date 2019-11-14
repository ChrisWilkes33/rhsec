import json
import sys
import requests
from datetime import datetime, timedelta
from xml.etree import ElementTree
import csv
import argparse

# parse argument for output file name
parser = argparse.ArgumentParser()
parser.add_argument("outfile", help="full path to output file")
parser.add_argument("version", help="version of rhel to retrieve: 7 or 8")
args = parser.parse_args()
url = "https://access.redhat.com/labs/securitydataapi"
outfile = args.outfile
version = args.version


def get_cve_json(baseurl):
    """
    takes RedHat security data api url and product variable and returns a json of every CVE for that product
    """
    endpoint = "/cve.json"
    params = 'product=linux 8'
    r = requests.get(baseurl+endpoint+'?'+params)
    #pretty_r = json.loads(r.text)
    #return json.dumps(pretty_r, indent=2)
    return r.json()


def get_cvrf_json(baseurl):
    """
    takes RedHat security data api url and returns a json block of every CVRF entry last 30 days
    """
    endpoint = "/cvrf.json"
    date = datetime.now() - timedelta(days=30)
    params = 'after='+str(date.date())
    r = requests.get(baseurl + endpoint + '?' + params)
    #pretty_r = json.loads(r.text)
    #return json.dumps(pretty_r, indent=2)
    return r.json()

#stuff = get_cvrf_json(url)
#for cvrf in stuff:
#    print(cvrf['RHSA'], cvrf['severity'], cvrf['released_on'], cvrf['CVEs'], cvrf['released_packages'])

stuff = get_cvrf_json(url)
#clear the output file
f = open(outfile, "w+")
f.close()
# get each cvrf and write out a csv file to outfile directory
for cvrf in stuff:
    #print(cvrf['RHSA'], cvrf['severity'], cvrf['CVEs'], cvrf['released_packages'])
    if cvrf['released_packages']:
        if 'el'+version in cvrf['released_packages'][0]:
            row = cvrf['RHSA'], cvrf['severity'], cvrf['CVEs'], cvrf['released_packages'][0]
            with open(outfile, 'a') as csvFile:
                writer = csv.writer(csvFile)
                writer.writerow(row)
            csvFile.close()

#stuff = get_cvrf_json(url)
#for cvrf in stuff:
#    print(cvrf)
#stuff = get_cve_json(url)
#print(stuff)
