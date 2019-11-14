import json
import sys
import requests
from datetime import datetime, timedelta
from xml.etree import ElementTree


url = "https://access.redhat.com/labs/securitydataapi"
outfile = "c:/users/wilkesc/file.csv"

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
for cvrf in stuff:
    #print(cvrf['RHSA'], cvrf['severity'], cvrf['CVEs'], cvrf['released_packages'])
    if cvrf['released_packages']:
        if 'el8' in cvrf['released_packages'][0]:
            print(cvrf['RHSA'], cvrf['severity'], cvrf['CVEs'], cvrf['released_packages'])

#stuff = get_cvrf_json(url)
#for cvrf in stuff:
#    print(cvrf)
#stuff = get_cve_json(url)
#print(stuff)
