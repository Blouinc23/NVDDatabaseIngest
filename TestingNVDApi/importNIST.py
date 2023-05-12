import json
from queue import Full
import string
from xmlrpc.client import boolean
import requests
import pandas 
import logging 
from pprint import pprint
import math
from datetime import datetime,date 
from SplunkIntegration import httpToSplunk,connectSplunk
        
class Vulnerability:
    def __init__(self,cve,cpeData,cweData,description,published_date,cvssDataV2, cvssDataV3):
        self.cve=cve
        self.cweData=cweData
        self.cpeData=cpeData
        self.description=description
        self.published_date=published_date
        self.cvssDataV2=cvssDataV2
        self.cvssDataV3=cvssDataV3

    def pushToSplunk():
        pass   
        #Write some code here to push this vulnerability to splunk

class VulnerabilyList:
    def __init__(self):
        pass
        #Write some code here to create list of a bunch of different vulnerabilities and push all of them one by one to splunk
class QueryLog:
    def __init__(self, date, searchType, host):
        self.date=date
        self.searhType=searchType
        self.host=host

def connectNIST(printOutput= False):
    #this code simply tests that there is an active connection to NIST before running a query
    global urlBase
    urlBase='https://services.nvd.nist.gov/rest/json/cves/2.0'
    extraString='?resultsPerPage=0&startIndex=0'
    fullURL=f'{urlBase}{extraString}'
    response = requests.get(fullURL)
    if response.status_code==200:
        if printOutput:
            pprint(response)
            print('Succesfully connected to NIST')                        
        return True 
    elif response.status_code != 200 and printOutput:
        if printOutput:
            print(f'No connection to NIST, status code {response.status_code}')    
        return False 

def queryCVEID(cveID:string):
    print('into CVEID')
    #Check to make sure that we can actually conncet to NIST 
    if connectNIST():
        extraString=f'?cveId={cveID}'
        fullURL=f'{urlBase}{extraString}'
        print(fullURL)
        response=requests.get(fullURL).json()['vulnerabilities']
        pprint(response)
        print(f'length of response is {len(response)}')
        
        #code if there is more than one response, dumps them all to csv for now
        if len(response)>1:
            vulnerabilities=[]
            for idx, i in enumerate(response):
                vulnerabilities.append(i['cve'])
                pprint(i['cve']['descriptions'][0]['value'])
                vulnData=pandas.DataFrame(vulnerabilities)
                vulnData.to_csv('queryTest.csv')
            print('Multiple vulnerbilities found, writing to csv')
        
        #If there is only a single response, it writes it to a vuln object
        #Might wanna create some pickle code to dump this somewhere
        elif len(response)==1:
            cve=response[0]['cve']['id']
            description=response[0]['cve']['descriptions'][0]['value']
            cpeData=response[0]['cve']['configurations'][0]['nodes'][0]['cpeMatch']
            cweData=response[0]['cve']['weaknesses']
            published_date=response[0]['cve']['published']
            cvssDataV2=response[0]['cve']['metrics']['cvssMetricV31']
            cvssDataV3=response[0]['cve']['metrics']['cvssMetricV2']
            #print(cve,description,cweData,published_date,cvssData)
            vuln=Vulnerability(cve,cpeData,cweData,description,published_date,cvssDataV2,cvssDataV3)
            #print(vuln)          
            return vuln   

def parseDesiredVulnData(vulnerabilities, pushToCsv=False, CSVName='test'):
    data=[]
    cveList=[]
    descriptionList=[]
    cweDataList=[]
    published_dateList=[]
    cvssDataV2List=[]
    cvssV2BaseSeverity=[]
    cvssV2BaseScore=[]
    cvssV2ExploitScore=[]
    cvssV2ImpactScore=[]
    cvssDataV3List=[]
    cvssV3BaseSeverity=[]
    cvssV3BaseScore=[]
    cvssV3ExploitScore=[]
    cvssV3ImpactScore=[]


    for i in vulnerabilities:
        data.append(i['cve'])
        cveList.append(i['cve']['id'])
        descriptionList.append(i['cve']['descriptions'][0]['value'])
        #cweDataList.append(i['cve']['weaknesses'])
        published_dateList.append(i['cve']['published'])
            

        #Checking to see fi there is cvssMetricV2
        if 'cvssMetricV2' in i['cve']['metrics']:
            cvssDataV2List.append(i['cve']['metrics']['cvssMetricV2'])
            cvssV2BaseSeverity.append(i['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'])
            cvssV2BaseScore.append(i['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore'])
            cvssV2ExploitScore.append(i['cve']['metrics']['cvssMetricV2'][0]['exploitabilityScore'])
            cvssV2ImpactScore.append(i['cve']['metrics']['cvssMetricV2'][0]['impactScore'])
        else:
            cvssDataV2List.append('None')
            cvssV2BaseSeverity.append('None')
            cvssV2BaseScore.append('None')
            cvssV2ExploitScore.append('None')
            cvssV2ImpactScore.append('None')
            

        #Checking to see if there is cvssMetricV31
        if 'cvssMetricV31' in i['cve']['metrics']:
            cvssDataV3List.append(i['cve']['metrics']['cvssMetricV31'])
            cvssV3BaseSeverity.append(i['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'])
            cvssV3BaseScore.append(i['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'])
            cvssV3ExploitScore.append(i['cve']['metrics']['cvssMetricV31'][0]['exploitabilityScore'])
            cvssV3ImpactScore.append(i['cve']['metrics']['cvssMetricV31'][0]['impactScore'])
        else: 
            cvssDataV3List.append('None')
            cvssV3BaseSeverity.append('None')
            cvssV3BaseScore.append('None')
            cvssV3ExploitScore.append('None')
            cvssV3ImpactScore.append('None')

            #Checking to see if there are weaknesses listed
        if 'weaknesses' in i['cve']:
            cweDataList.append(i['cve']['weaknesses'])
        else:
            cweDataList.append('None')

        pandasDataFrame = pandas.DataFrame(
            {'CVE':cveList, 'Description':  descriptionList, 'Weakness Data': cweDataList, 
            'Published Date': published_dateList, 'cvssMetricV2': cvssDataV2List, 'cvssMetricV3':cvssDataV3List,  
            'cvssV2 Severity Level': cvssV2BaseSeverity,'cvssV2 Base Score': cvssV2BaseScore, 
            'cvssV2 Exploitability Score':cvssV2ExploitScore,'cvssV2 Impactabilitiy Score':cvssV2ImpactScore,
            'cvssV3 Severity Level': cvssV3BaseSeverity, 'cvssV3BaseScore': cvssV3BaseScore, 
            'cvssV3 Exploitability': cvssV3ExploitScore, 'cvssV3 Impactability Score':cvssV3ImpactScore})
        
    if pushToCsv:
        print(f'Pushing output to csv file with name {CSVName}')
        print(pandasDataFrame)
        pandasDataFrame.to_csv(CSVName)
    else: 
        return pandasDataFrame


def queryKeywordSearch(keywords:string, startIndex=0, exact=False, pushToCSV=False, CSVName='test'):
    print('Keyword Search Initiated')

    #checks to make sure we can connect to NIST
    if connectNIST():
        if not exact:
            extraString=f'?keywordSearch={keywords}'            
        else:
            extraString=f'?keywordSearch={keywords}&keywordExactMatch'

        fullUrl=f'{urlBase}{extraString}'
        response=requests.get(fullUrl).json()

        totalResults=response["totalResults"]
        resultsPerPage=response["resultsPerPage"]
        print(f"Number of responses: {totalResults}")
        print(f"Results shown here: {resultsPerPage}")
        
        #Need to offset queiries by starting index in the event that there are more results than what is shown here
        if totalResults>=resultsPerPage:
            print("Number of results greater than results found in this query, consider running another query with a startindex=2000")
            searchesNeeded=math.floor(totalResults/resultsPerPage)
            print(f"Would need at least {searchesNeeded} more searches to get all the results")


        vulnerabilities = response['vulnerabilities']
        #pprint(response)
        print(f'length of response is {len(vulnerabilities)}')
        df=parseDesiredVulnData(vulnerabilities, pushToCSV, CSVName)
        return df

def queryDateSearch(startYear,startMonth,endYear,endMonth, startIndex=0, pushToCSV=False):
    #checks to make sure we can connect to NIST
    if connectNIST():
        pubStartDate=datetime(startYear,startMonth,1,0,0,0,0).isoformat()
        pubEndDate=datetime(endYear,endMonth,1,0,0,0,0).isoformat()
        print(f'Start date is {pubStartDate} and end date is {pubEndDate}')
        
        extraString=f'?pubStartDate={pubStartDate}&pubEndDate={pubEndDate}'

        fullUrl=f'{urlBase}{extraString}'
        print(fullUrl)
        response=requests.get(fullUrl).json()

        totalResults=response["totalResults"]
        resultsPerPage=response["resultsPerPage"]
        print(f"Number of responses: {totalResults}")
        print(f"Results shown here: {resultsPerPage}")

        #Need to offset queiries by starting index in the event that there are more results than what is shown here
        if totalResults>=resultsPerPage:
            print("Number of results greater than results found in this query, consider running another query with a startindex=2000")
            searchesNeeded=math.floor(totalResults/resultsPerPage)
            print(f"Would need at least {searchesNeeded} more searches to get all the results")

        vulnerabilities = response['vulnerabilities']
        #pprint(response)
        print(f'length of response is {len(vulnerabilities)}')
        parseDesiredVulnData(vulnerabilities, pushToCSV, 'queryDateSearch1.csv')    

def NISTDataIngest():
    pass

if __name__ == '__main__':
    #queryCVEID('CVE-2019-1010218')
    searchTest=queryKeywordSearch('Microsoft', exact=False, pushToCSV=False, CSVName='')
    #print(datetime(2021,1,1,0,0,0,0).isoformat())
    #queryDateSearch(2021,1,2021,3,startIndex=0,pushToCSV=True)
    # print(f'Data from keyword search is {}')
    testData=searchTest.iloc[3,0:7]
    # print(testData)

    service = connectSplunk()
    pandas.set_option("display.max_colwidth", 10000)
    print(testData.to_string().replace(' ', '-:-').replace('-:-',' , '))
    
    # httpToSplunk(service, data=testData.to_csv(sep=':'),indexName='devtestindex2',createIndex=True)

