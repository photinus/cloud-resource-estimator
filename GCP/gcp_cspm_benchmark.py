"""
gcp-cspm-benchmark.py

Assists with provisioning calculations by retrieving a count
of all billable resources attached to a GCP project.
"""

import csv
import logging
from functools import cached_property
import google.api_core.exceptions
from google.cloud import logging_v2
from google.cloud.resourcemanager import ProjectsClient
from google.cloud.resourcemanager_v3.types import Project
from google.cloud import compute
from googleapiclient import discovery


LOG_LEVEL = logging.INFO
LOG_LEVEL = logging.DEBUG
log = logging.getLogger('gcp')
log.setLevel(LOG_LEVEL)
ch = logging.StreamHandler()
ch.setLevel(LOG_LEVEL)
formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s', '%Y-%m-%d %H:%M:%S')
ch.setFormatter(formatter)
log.addHandler(ch)


class GCP:
    def projects(self):
        return ProjectsClient().search_projects()

    def vms(self, project_id):
        pass

    def list_instances(self, project_id):
        request = compute.AggregatedListInstancesRequest(max_results=50, project=project_id)
        return self.instances_client.aggregated_list(request=request)

    def clusters(self, project_id):
        try:
            service = discovery.build('container', 'v1')
            endpoint = service.projects().zones().clusters()  # pylint: disable=no-member
            request = endpoint.list(projectId=project_id, zone='-')
            response = request.execute()
            return response.get('clusters', [])
        except:
            log.debug('Skipping')
            return []
        

    @cached_property
    def instances_client(self):
        return compute.InstancesClient()

    @classmethod
    def is_vm_kubenode(cls, instance):
        return any(k.key for k in instance.metadata.items if k.key == 'kubeconfig')

    @classmethod
    def is_vm_running(cls, instance):
        return instance.status != 'TERMINATED'

    @classmethod
    def is_cluster_autopilot(cls, cluster):
        return cluster.get('autopilot', {}).get('enabled', False)


def process_gcp_project(project):  # pylint: disable=redefined-outer-name
    result = {'project_id': project.project_id,
              'kubenodes_running': 0, 'kubenodes_terminated': 0,
              'vms_running': 0, 'vms_terminated': 0}
    log.info("Exploring GCP project: %s", project.display_name)

    try:
        # (1) Process GKE clusters
        for cluster in gcp.clusters(project.project_id):
            if GCP.is_cluster_autopilot(cluster):
                log.error("Skipping GKE Autopilot cluster %s in project: %s", cluster['name'], project.display_name)

        # (2) Process instances
        for _zone, response in gcp.list_instances(project.project_id):
            if response.instances:
                for instance in response.instances:
                    typ = 'kubenode' if GCP.is_vm_kubenode(instance) else 'vm'
                    state = 'running' if GCP.is_vm_running(instance) else 'terminated'
                    key = f"{typ}s_{state}"
                    result[key] += 1

    except google.api_core.exceptions.Forbidden as exc:
        log.error("ERROR: cannot explore project: %s: %s", project.display_name, exc)

    return result


data = []
totals = {'project_id': 'totals',
          'kubenodes_running': 0, 'kubenodes_terminated': 0,
          'vms_running': 0, 'vms_terminated': 0}


def get_gcp_logging_details(project):  # pylint: disable=redefined-outer-name
    gcp_logging_client = logging_v2.services.config_service_v2.ConfigServiceV2Client()
    parent = "projects/" + project.project_id
    rows = []

    # Initialize request argument(s)
    request = logging_v2.types.ListSinksRequest(parent=parent)

    # Make the request
    page_result = gcp_logging_client.list_sinks(request=request)

    # Handle the response
    for response in page_result:
        sink_row = {'project_id': project.project_id,
                    'sink_name': response.name, 'sink_destination': response.destination,
                    'sink_filter': response.filter}
        rows.append(sink_row)

    return rows


def get_gcp_service_account_count(project):  # pylint: disable=redefined-outer-name

    iam_client = discovery.build("iam", "v1")

    service_accounts = (
        iam_client.projects()  # pylint: disable=no-member
        .serviceAccounts()
        .list(name="projects/" + project.project_id)
        .execute()
    )

    service_account_count = len(service_accounts['accounts'])

    return service_account_count


gcp = GCP()

logging_rows = []
service_account_rows = {}
for project in gcp.projects():  # pylint: disable=redefined-outer-name
    if project.state == Project.State.DELETE_REQUESTED:
        log.debug("Skipping GCP project %s (project pending deletion)", project.display_name)
        continue

    row = process_gcp_project(project)
    if row:
        data.append(row)
        for k in totals:
            if k == 'project_id':
                continue

            totals[k] += row[k]

    logging_details = get_gcp_logging_details(project)
    if logging_details:
        logging_rows += logging_details

    service_account_rows[project.project_id] = get_gcp_service_account_count(project)

data.append(totals)

headers = ['project_id', 'kubenodes_running', 'kubenodes_terminated', 'vms_running', 'vms_terminated']
with open('gcp-benchmark.csv', 'w', newline='', encoding='utf-8') as csv_file:
    csv_writer = csv.DictWriter(csv_file, fieldnames=headers)
    csv_writer.writeheader()
    csv_writer.writerows(data)

log.info("CSV Resource summary has been exported to ./gcp-benchmark.csv file")

headers = ['project_id', 'sink_name', 'sink_destination', 'sink_filter']
with open('gcp-logging-config.csv', 'w', newline='', encoding='utf-8') as csv_file:
    csv_writer = csv.DictWriter(csv_file, fieldnames=headers)
    csv_writer.writeheader()
    csv_writer.writerows(logging_rows)

log.info("CSV Logging summary has been exported to ./gcp-logging-config.csv file")

headers = ['project_id', 'type', 'value']
with open('gcp-iam-details.csv', 'w', newline='', encoding='utf-8') as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(headers)
    for pro_id in service_account_rows:  # pylint: disable=consider-using-dict-items
        sa_count = service_account_rows[pro_id]
        csv_writer.writerow([pro_id, 'service_account_total', sa_count])

log.info("CSV Logging summary has been exported to ./gcp-iam-details.csv file")
