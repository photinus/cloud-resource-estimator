import boto3
import glob

from datetime import datetime


class Upload:

    def __init__(self, bucket):
        self.bucket = bucket
        self.s3 = boto3.resource('s3')
        self.folder = datetime.now().strftime("%m_%d_%Y_%H_%M_%S")

    def find_files(self):
        return glob.glob("*.csv") 
 
    def upload(self):
        for file in self.find_files():
            s3.Bucket(self.bucket).upload_file(file, self.folder + "/file")