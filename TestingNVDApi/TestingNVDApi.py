import json
import requests
import pandas 
from pprint import pprint

def main():
    # response = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0')
    # print(response.status_code)

    # vuln=response.json()['vulnerabilities']
    # #pprint(vuln)

    # testId=response.json()['vulnerabilities'][0]['cve']
    # pprint(testId)

    # #Trying to get everything in the cve parameter
    # data=[]
    # for i in response.json()['vulnerabilities']:
    #     data.append(i['cve'])

    # df=pandas.DataFrame(data)
    # df.head()
    # df.all()

    # #pprint(df.head())
    # #pprint(df)

    # df.to_csv('fullDatabase.csv')
    response = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0').json()['vulnerabilities']
    cpe=response[1]['cve']['configurations'][0]['nodes'][0]['cpeMatch']
    severity=response[1]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity']
    pprint(severity)
    #pprint(cpe)

    #testFrame=pandas.DataFrame({'Col 1':[1,2,3], 'Col 2':[1,2,3]})
    #print(testFrame)


if __name__ == '__main__':
    main()
