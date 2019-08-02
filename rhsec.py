import json
import sys
import requests

url = "https://access.redhat.com/labs/securitydataapi"


def get_cve_json(baseurl):
    """
    takes RedHat security data api url and returns a json of every CVE
    """
    endpoint = "/cve.json"
    r = requests.get(baseurl+endpoint)
    #pretty_r = json.loads(r.text)
    #return json.dumps(pretty_r, indent=2)
    return r.json()


def get_cvrf_json(baseurl):
    """
    takes RedHat security data api url and returns a json block of every CVRF entry
    """
    endpoint = "/cvrf.json"
    r = requests.get(baseurl + endpoint)
    #pretty_r = json.loads(r.text)
    #return json.dumps(pretty_r, indent=2)
    return r.json()


stuff = get_cvrf_json(url)
#print(stuff)
for cvrf in stuff:
    print(cvrf['RHSA'], cvrf['severity'], cvrf['released_on'], cvrf['CVEs'], cvrf['released_packages'])

