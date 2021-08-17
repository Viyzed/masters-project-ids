import datetime
import boto3
import logging
from botocore.exceptions import ClientError
import json

class GetLogs:
    
    filename = ''
    timestamp = ''

    def __init__(self):
        self.bucket_name = 'masters-lb-access-logs'
        self.object_name = 'instance-logs/'

    def getFileNames(self):
        s3_resource = boto3.resource('s3')
        s3_bucket = s3_resource.Bucket(self.bucket_name)
        file_summaries = s3_bucket.objects.all()
        files = []
        for file in file_summaries:
            if self.object_name in file.key:
                files.append(file.key)

        return files[1:]

    def downloadFile(self, name):
        s3_client = boto3.client('s3')
        self.timestamp = datetime.datetime.now()
        self.timestamp = self.timestamp.strftime('%m') + '-' + self.timestamp.strftime('%d') + '-' + self.timestamp.strftime('%y') + '-' + self.timestamp.strftime('%X')
        self.filename = str(self.timestamp+'_capture.pcap')
        s3_client.download_file(self.bucket_name, name, 'pcaps/'+name.split('/')[1])
    
    def deleteFile(self, arraylen, filename):
        s3_client = boto3.client('s3')
        if (arraylen > 10):
            response = s3_client.delete_object(
                Bucket=self.bucket_name,
                Key=self.filename
            )
            return True
        else: 
            return False

    '''
    if __name__ == "__main__":
        while True:
            if(deleteFile(len(getFileNames()), getFileNames()[0]) == False):
                download_name = getFileNames()
                downloadFile(download_name[0])
    '''

get = GetLogs()

while True:
    if (get.deleteFile(len(get.getFileNames()), get.getFileNames()[0]) == False):
        download_name = get.getFileNames()
        get.downloadFile(download_name[0])

