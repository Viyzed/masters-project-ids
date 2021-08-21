import datetime
import boto3
import logging
from botocore.exceptions import ClientError
import json

class GetLogs:
    
    # global filename and timestamp for pcap file and path for S3 bucket
    global filename, timestamp, bucket_name, object_name
    filename = ''
    timestamp = ''
    bucket_name = 'masters-lb-access-logs'
    object_name = 'instance-logs/'

    # get all filenames of files currently stored in the S3 bucket
    def getFileNames():
        s3_resource = boto3.resource('s3')
        s3_bucket = s3_resource.Bucket(bucket_name)
        file_summaries = s3_bucket.objects.all()
        files = []
        for file in file_summaries:
            if object_name in file.key:
                files.append(file.key)

        return files[1:]

    # download the pcap file to localhost
    def downloadFile(name):
        s3_client = boto3.client('s3')
        timestamp = datetime.datetime.now()
        timestamp = timestamp.strftime('%m') + '-' + timestamp.strftime('%d') + '-' + timestamp.strftime('%y') + '-' + timestamp.strftime('%X')
        filename = str(timestamp+'_capture.pcap')
        s3_client.download_file(bucket_name, name, 'pcaps/'+name.split('/')[1])
    
    # delete file from S3 bucket if there are more than 2 files stored
    def deleteFile(arraylen, filename):
        s3_client = boto3.client('s3')
        if (arraylen > 2):
            response = s3_client.delete_object(
                Bucket=bucket_name,
                Key=filename
            )
            return True
        else: 
            return False

    if __name__ == "__main__":
        while True:
            # if file is deleted from the bucket, get new file from bucket
            if(deleteFile(len(getFileNames()), getFileNames()[0]) == True):
                download_name = getFileNames()
                downloadFile(download_name[0])

