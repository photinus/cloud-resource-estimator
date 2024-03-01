"""
aws-cspm-benchmark.py

Assists with provisioning calculations by retrieving a count of
all billable resources attached to an AWS account.
"""
import argparse
import csv
import glob
from datetime import datetime
from azure.storage.blob import BlobClient
import boto3
from tabulate import tabulate


data = []
cloudtrails = []
headers = {
    'account_id': 'AWS Account ID',
    "region": "Region",
    "vms_terminated": "Terminated VMs",
    "vms_running": "Running VMs",
    'kubenodes_terminated': "Terminated Kubernetes Nodes",
    'kubenodes_running': "Running Kubernetes Nodes"
}
totals = {
    "region": "TOTAL",
    'account_id': 'TOTAL',
    "vms_terminated": 0,
    "vms_running": 0,
    'kubenodes_terminated': 0,
    'kubenodes_running': 0
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze AWS accounts and regions for EC2 instances and Kubernetes nodes.")
    parser.add_argument(
        "-r", "--role_name",
        default="OrganizationAccountAccessRole",
        help="Specify a custom role name to assume into.")
    parser.add_argument(
        "-b", "--blob_string",
        default=None,
        help="Connection string to upload files to Azure Blob")
    return parser.parse_args()


def upload(connection_string):

    prefix = datetime.now().strftime("%m_%d_%Y_%H_%M_%S_")
    cs_split = connection_string.split("?")

    for file in glob.glob("*.csv"):
        with open(file, "rb") as file_data:
            filename = prefix + file
            blob_url = cs_split[0] + "/" + filename + "?" + cs_split[1]
            blob_client = BlobClient.from_blob_url(blob_url=blob_url)
            blob_client.upload_blob(name=filename, data=file_data, overwrite=True)


class AWSOrgAccess:
    def __init__(self):
        self.master_session = boto3.session.Session()
        self.master_sts = self.master_session.client('sts')
        self.master_account_id = self.master_sts.get_caller_identity()["Account"]

    def accounts(self):
        try:
            client = boto3.client('organizations')
            response = client.list_accounts()
            accounts = response['Accounts']
            next_token = response.get('NextToken', None)

            while next_token:
                response = client.list_accounts(NextToken=next_token)
                accounts += response['Accounts']
                next_token = response.get('NextToken', None)

            # We only want accounts that are in ACTIVE state
            # Permissable values are: 'ACTIVE'|'SUSPENDED'|'PENDING_CLOSURE'
            active_accounts = [a for a in accounts if a['Status'] == 'ACTIVE']

            return [self.aws_handle(a) for a in active_accounts if self.aws_handle(a)]
        except client.exceptions.AccessDeniedException:
            print("Cannot autodiscover adjacent accounts: cannot list accounts within the AWS organization")
            return [AWSHandle()]

    def aws_handle(self, account):
        if account['Id'] == self.master_account_id:
            return AWSHandle(aws_session=self.master_session, account_id=self.master_account_id)

        # Check if new_session returns a session object
        session = self.new_session(account['Id'])
        if session:
            return AWSHandle(aws_session=session, account_id=account['Id'])

        return None

    def new_session(self, account_id):
        try:
            credentials = self.master_sts.assume_role(
                RoleArn=f'arn:aws:iam::{account_id}:role/{args.role_name}',
                RoleSessionName=account_id
            )
            return boto3.session.Session(
                aws_access_key_id=credentials['Credentials']['AccessKeyId'],
                aws_secret_access_key=credentials['Credentials']['SecretAccessKey'],
                aws_session_token=credentials['Credentials']['SessionToken'],
                region_name='us-east-1'
            )
        except self.master_sts.exceptions.ClientError as exc:
            # Print the error and continue.
            # Handle what to do with accounts that cannot be accessed
            # due to assuming role errors.
            print("Cannot access adjacent account: ", account_id, exc)
            return None


class AWSHandle:
    EKS_TAGS = ['eks:cluster-name', 'alpha.eksctl.io/nodegroup-type', 'aws:eks:cluster-name', 'eks:nodegroup-name']

    def __init__(self, aws_session=None, account_id=None):
        self.aws_session = aws_session if aws_session else boto3.session.Session()
        self.acc_id = account_id

    @property
    def regions(self):
        return self.ec2.describe_regions()['Regions']

    def ec2_instances(self, aws_region):
        client = self.aws_session.client('ec2', aws_region)

        response = client.describe_instances(MaxResults=1000)
        instances = response['Reservations']
        next_token = response['NextToken'] if 'NextToken' in response else None

        while next_token:
            response = client.describe_instances(MaxResults=1000, NextToken=next_token)
            instances += response['Reservations']
            next_token = response['NextToken'] if 'NextToken' in response else None

        return instances

    @property
    def ec2(self):
        return self.aws_session.client("ec2")

    @classmethod
    def is_vm_kubenode(cls, vm):
        return any(True for tag in vm.get('Tags', []) if tag['Key'] in cls.EKS_TAGS)

    @classmethod
    def is_vm_running(cls, vm):
        return vm['State']['Name'] != 'stopped'

    @property
    def account_id(self):
        if self.acc_id is None:
            sts = self.aws_session.client('sts')
            self.acc_id = sts.get_caller_identity()["Account"]

        return self.acc_id

    @property
    def iam(self):
        return self.aws_session.client("iam")

    def users_conut(self):

        client = self.iam

        response = client.list_users(MaxItems=1000)
        users = response['Users']
        next_token = response['NextToken'] if 'NextToken' in response else None

        while next_token:
            response = client.describe_instances(MaxItems=1000, NextToken=next_token)
            users += response['Users']
            next_token = response['NextToken'] if 'NextToken' in response else None

        return len(users)

    def roles_conut(self):

        client = self.iam

        response = client.list_roles(MaxItems=1000)
        roles = response['Roles']
        next_token = response['NextToken'] if 'NextToken' in response else None

        while next_token:
            response = client.describe_instances(MaxItems=1000, NextToken=next_token)
            roles += response['Roles']
            next_token = response['NextToken'] if 'NextToken' in response else None

        return len(roles)

    def cloudtrail_instances(self, aws_region):
        cl_client = self.aws_session.client('cloudtrail', aws_region)
        # s3_client = self.aws_session.client('s3', aws_region)

        return cl_client.describe_trails()['trailList']


args = parse_args()

for aws in AWSOrgAccess().accounts():
    for region in aws.regions:
        RegionName = region["RegionName"]

        # Setup the branch
        print(f"Processing {RegionName}")
        # Create the row for our output table
        row = {'account_id': aws.account_id, 'region': RegionName,
               'vms_terminated': 0, 'vms_running': 0,
               'kubenodes_terminated': 0, 'kubenodes_running': 0}

        # Count ec2 instances
        for reservation in aws.ec2_instances(RegionName):
            for instance in reservation['Instances']:
                typ = 'kubenode' if AWSHandle.is_vm_kubenode(instance) else 'vm'
                state = 'running' if AWSHandle.is_vm_running(instance) else 'terminated'
                key = f"{typ}s_{state}"
                row[key] += 1

        for k in ['vms_terminated', 'vms_running', 'kubenodes_terminated', 'kubenodes_running']:
            totals[k] += row[k]

        # Add the row to our display table
        data.append(row)

        # Get CloudTrail details
        cloudtrails += aws.cloudtrail_instances(RegionName)

    # Add in our grand totals to the display table
data.append(totals)

# Get IAM details
iam_counts = {}
for aws in AWSOrgAccess().accounts():
    iam_counts[aws.account_id] = [aws.users_conut(), aws.roles_conut()]

# Output our results
print(tabulate(data, headers=headers, tablefmt="grid"))

with open('aws-benchmark.csv', 'w', newline='', encoding='utf-8') as csv_file:
    csv_writer = csv.DictWriter(csv_file, fieldnames=headers.keys())
    csv_writer.writeheader()
    csv_writer.writerows(data)

headers = ['account_id', 'users', 'roles']
with open('aws-iam-details.csv', 'w', newline='', encoding='utf-8') as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(headers)
    for acc in iam_counts:  # pylint: disable=consider-using-dict-items
        ucount, rcount = iam_counts[acc]
        csv_writer.writerow([acc, ucount, rcount])

print("\nCSV files stored in: ./aws-benchmark.csv\n")

headers = cloudtrails[0].keys()
with open('cloudtrails.csv', 'w', newline='', encoding='utf-8') as csv_file:
    dict_writer = csv.DictWriter(csv_file, headers)
    dict_writer.writeheader()
    dict_writer.writerows(cloudtrails)

if args.blob_string:
    container = args.blob_string.split("/")[3].split("?")[0]
    print(f"Uploading output files to provided Azure container: {container}\n")
    upload(args.blob_string)
    print(f"CSV files uploaded to Azure container: {container}\n")

#     .wwwwwwww.
#   .w"  "WW"  "w.
#  ."   /\  /\   ".
# |\     o  o     /|
#  \|  ___\/___  |/
#  / \ \_v__v_/ / \
# / | \________/ | \
# >  \   WWWW   /  <
# \   \   ""   /   /
#  \   \      /   /
#  The Count says...
#
#  That's ONE server, TWO servers  ... AH AH AH!
