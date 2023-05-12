import sys
import os
import splunklib.client as client

def connectSplunk():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

    try:
        #Putting in host and port information along with generated splunk bearer token
        HOST = "localhost"
        PORT = 8089
        BEARER_TOKEN = "eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJibG91aW5jMjMgZnJvbSBMRUdJT04iLCJzdWIiOiJibG91aW5jMjMiLCJhdWQiOiJkZXZUb2tlbiIsImlkcCI6IlNwbHVuayIsImp0aSI6IjFhMDI5YmFlZGI4Y2JjYzkzOWM1MGM2Y2Q5OTI4YzZmOWQ0YTE2Y2U1MjQ2ZDk4YjUxYWJlOGQ5ZWFmMTBkNGMiLCJpYXQiOjE2ODEzMDc0MjcsImV4cCI6MTY4Mzg5OTQyNywibmJyIjoxNjgxMzA3NDI3fQ.klpjHxi1KBFRm-L-6ClTaYFPunkan3dD9UjXl8ZWkRlui4TSlwz1Jxx2QjuPlgF1Y5Ry5p4euQUiUcsG99TjOA"
        #USERNAME='admin'
        #PASSWORD='Bluebird2?'

        # Create a Service instance and log in 
        service = client.connect(
            host=HOST,
            port=PORT,
            splunkToken=BEARER_TOKEN,
            #username=USERNAME,
            #password=PASSWORD
            #basic=True,
            #autologin=True
            )

        print('Connected to splunk using bearer token.')
        return service

    
    except Exception as e:
        print(e)


def sockToSplunk(splunkService:object, indexName:str, createIndex:True):
    #the createIndex bool will check to see if the indexName passed throught exists
    #if it doesn't it will create the index 

    if createIndex:
            if checkIndexExists(service, indexName):
                print('Index already exists, continuing...')
            else:
                createSplunkIndex(service,indexName)
                print(f'Index {indexName} created, continuing...')

    myIndex=splunkService.indexes[indexName]
    socket=myIndex.attach(sourcetype='devTest',host='localhost')
    data='test event longerlonger4longer4longer4longer4longer4longer4 4-12'
    #socket.send(data.encode('utf-8'))
    #socket.close()
    
    with myIndex.attached_socket(sourcetype='devTest') as sock:
        sock.send(data.encode('utf-8'))
    
    #this currently isn't working. Seems to look like it's pushing data to splunk, but I can't find it in the library of data at all. Going to try and use the upload feature in the SDK instead. 

    print('Data pushed to splunk succesfully')

def httpToSplunk(splunkService:object, data, indexName:str, createIndex:True):
    if createIndex:
            if checkIndexExists(splunkService, indexName):
                print('Index already exists, continuing...')
            else:
                createSplunkIndex(splunkService,indexName)
                print(f'Index {indexName} created, continuing...')
    
    myIndex = splunkService.indexes[indexName]
    myIndex.submit(data, sourcetype="test.log", host="local")


def createSplunkIndex(splunkService:object, indexName:str):
    if checkIndexExists(splunkService, indexName):
        print("Index already created, skipping...")
    else:
        myIndex=splunkService.indexes.create(indexName)
        print(f'Index {indexName} created')


def deleteSplunkIndex(splunkService:object, indexName:str):
    if not checkIndexExists(splunkService, indexName):
        print("Index does not exist or has already been deleted")
    else:
        myIndex=splunkService.indexes.delete(indexName)
        print(f'Index {indexName} deleted')


def checkIndexExists(splunkService:object, indexName:str):
    indexList=[]
    for index in splunkService.indexes:
        indexList.append(index.name)
    
    if (indexName in indexList):
        return True
    else:
        return False
    

    
if __name__ == '__main__':
    service = connectSplunk()
    print(service.indexes)

    httpToSplunk(service, 'devtestindex1', True)

    for index in service.indexes:
        print(index.name)



    



