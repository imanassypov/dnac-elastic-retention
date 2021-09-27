#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Copyright (c) 2021 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

__author__ = "Gabriel Zapodeanu TME, ENB"
__email__ = "gzapodea@cisco.com"
__author__ = "Igor Manassypov, System Architect"
__email__ = "imanassy@cisco.com"
__version__ = "0.1.0"
__copyright__ = "Copyright (c) 2021 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

import datetime
import logging
import os
import time
import urllib3
import json
import requests
import sys
import click

import dnacenter_elastic
import dnacenter_reports

from datetime import datetime, timezone, timedelta
from dateutil.relativedelta import relativedelta
from dotenv import load_dotenv, dotenv_values
from requests.auth import HTTPBasicAuth  # for Basic Auth
from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings

from timeit import default_timer as timer

# ENVIRONMENT VARIABLES (CREDENTIALS)
ENV_FILE = 'environment.env'

# DNAC Location strings use a delimiter to delineate area/building/floor identifiers
# this delimiter is used to split the string into descrete site hierarchy elements
# to import into Elastic
SITE_HIERARCHY_DELIMITER = '/'

# If the script is run as crontab job (as root)
# we need to supply a full path to where the .env file is located
# and we will load auth parameters from the file's absolute path
# directory from which the script is run
dn = os.path.dirname(os.path.realpath(__file__))
# path to environment file with credentials definitions
env_full_path = os.path.join(dn,ENV_FILE)

# The function dotenv_values works more or less the same way as load_dotenv, 
# except it doesn't touch the environment, 
# it just returns a dict with the values parsed from the .env file.
env_dict = dotenv_values(env_full_path)

try:
    DNAC_URL = env_dict['DNAC_URL']
    DNAC_USER = env_dict['DNAC_USER']
    DNAC_PASS = env_dict['DNAC_PASS']

    ELASTIC_URL = env_dict['ELASTIC_URL']
    ELASTIC_USER = env_dict['ELASTIC_USER']
    ELASTIC_PASS = env_dict['ELASTIC_PASS']
except Exception as e:
    logging.debug("ENV variables in file {0} not set. Exiting.".format(env_full_path))
    print("ENV variables in file {0} not set. Exiting.".format(env_full_path))
    sys.exit(1)

# os.environ['TZ'] = 'America/Los_Angeles'  # define the timezone for PST
# time.tzset()  # adjust the timezone, more info https://help.pythonanywhere.com/pages/SettingTheTimezone/

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings


DNAC_AUTH = HTTPBasicAuth(DNAC_USER, DNAC_PASS)

#report 'to' and 'from' dates
DATE_PRINT_FORMAT='%Y-%m-%d %H:%M:%S'
REPORT_NAME_DATE_FORMAT='%Y-%m-%d'
MILLISECONDS = 1000

# REPORT_DATE_TO = datetime.now().replace(tzinfo=timezone.utc, day=1,hour=23,minute=59,second=59) - timedelta(days=1)
# REPORT_DATE_FROM = datetime.now().replace(tzinfo=timezone.utc, day=1,hour=0,minute=0,second=0) - timedelta(days=REPORT_DATE_TO.day)

#REPORT_CATEGORY = 'Client'
#VIEW_NAME = 'Client Detail'
REPORT_CATEGORY = 'Rogue and aWIPS'
VIEW_NAME = 'Threat Detail'

# REPORT_NAME = VIEW_NAME +  " MONTHLY " + REPORT_DATE_TO.strftime(REPORT_NAME_DATE_FORMAT)

#Elastic parameters
# ELASTIC_INDEX = 'andrew_index2'.lower()
ELASTIC_INDEX = 'dnac_rogue_threat_detail'
ELASTIC_INDEX = ELASTIC_INDEX.lower() # index must be lowercase
#verbose output
VERBOSE = False

#DNAC Location scope
#Location scope expects Location Id Object
#Caveat: Location ID scope can not contain more than 254 elements
#If scoping is required, Location filter should be populated with a list of 254 Floors
#and API called in chunks of 254 elements
#REPORT_LOCATION = [{}]


def pprint(json_data):
    """
    Pretty print JSON formatted data
   :param json_data: data to pretty print
   :return None
    """
    print(json.dumps(json_data, indent=4, separators=(', ', ': ')))


def get_dnac_jwt_token(dnac_auth):
    """
    Create the authorization token required to access DNA C
   :param dnac_auth - Cisco DNA Center Basic Auth string
   :return: Cisco DNA Center JWT token
    """
    dnac_jwt_token = 0
    url = DNAC_URL + '/dna/system/api/v1/auth/token'
    header = {'content-type': 'application/json'}
    response = requests.post(url, auth=dnac_auth, headers=header, verify=False)
    if(response.status_code == requests.codes.ok):
        dnac_jwt_token = response.json()['Token']
    else:
        if VERBOSE:
            print("Authentication to DNAC failed. Status: ", response.status_code)
            logging.debug("Authentication to DNAC failed. Status: : {0}".response)
        sys.exit(1)

    if VERBOSE:
        print ("Connected to DNAC {0}. Status: {1}\n".format(DNAC_URL, response.status_code))
        logging.info("Connected to DNAC {0}. Status: {1}\n".format(DNAC_URL, response.status_code))
    return dnac_jwt_token


def get_sites_coordinates(dnac_auth: str):
    """
    This function will return the location information for all sites
   :param dnac_auth: Cisco DNA Center Auth
   :return: list of sites
    """
    url = DNAC_URL + '/dna/intent/api/v1/topology/site-topology'
    header = {'Content-Type': 'application/json', 'X-Auth-Token': dnac_auth}
    response = requests.get(url, headers=header, verify=False)
    if response.status_code == 200:
        sites = response.json()['response']['sites']
        return sites
    else:
        print(response.text)
        return []


def get_site_geojson(siteHierarchyName: str, sites: list):
    """
    This function will return the location information for all sites
   :param siteHierarchyName: Name of site to be searched
   :param sites: List of sites to be searched, get from single API call using get_sites_cooridnates
   :return: GeoJson for that site
    """
    if sites:
        for site in sites:
            if site["groupNameHierarchy"] == siteHierarchyName:
                if site['longitude'] and site['latitude']:
                    mypoint = [round(float(site['longitude']), 2), round(float(site['latitude']), 2)]
                    return mypoint
    # If nothing found, return a blank point
    # return []
    return [-79.347015, 43.651070] # For debugging, return Toronto

def get_report_view_groups(dnac_auth):
    """
    This function will return the report view groups
   :param dnac_auth: Cisco DNA Center Auth
   :return: report view groups
    """
    url = DNAC_URL + '/dna/intent/api/v1/data/view-groups'
    header = {'Content-Type': 'application/json', 'X-Auth-Token': dnac_auth}
    response = requests.get(url, headers=header, verify=False)
    report_view_groups = response.json()
    return report_view_groups

def get_report_view_group_id(report_category: str, dnac_auth: str):
    """
    This function will return the report view group id
   :param dnac_auth: Cisco DNA Center Auth
   :param dnac_auth: Report Category Name
   :return: report view groups
    """
    view_group_id = ''
    report_view_groups = get_report_view_groups(dnac_auth)
    for view in report_view_groups:
        if view['category'] == report_category:
            view_group_id = view['viewGroupId']
    return view_group_id

def get_report_view_ids(view_group_id: str, dnac_auth: str):
    """
    This function will get return the views for the groups id {view_group_id}
   :param view_group_id: report view group id
   :param dnac_auth: Cisco DNA Center Auth
   :return: the report view ids
    """
    url = DNAC_URL + '/dna/intent/api/v1/data/view-groups/' + view_group_id
    header = {'Content-Type': 'application/json', 'X-Auth-Token': dnac_auth}
    response = requests.get(url, headers=header, verify=False)
    report_view_ids = response.json()
    return report_view_ids

def get_report_view_id_by_name(view_name: str, view_group_id: str, dnac_auth: str):
    """
    This function will get return the specific report id matching a name
   :param view_name: report view name, ie report name
   :param dnac_auth: Cisco DNA Center Auth
   :return: the report view id with matching report name
    """
    report_view_id = ''
    report_view_ids = get_report_view_ids(view_group_id, dnac_auth)
    report_views = report_view_ids['views']
    for view in report_views:
        if view['viewName'] == view_name:
            report_view_id = view['viewId']
    return report_view_id

def get_detailed_report_views(view_id: str, group_id: str, dnac_auth: str):
    """
    This function will retrieve the view details for the view group id {group_id} and the view id {view_id}
   :param view_id: report view id
   :param group_id: report group id
   :param dnac_auth: Cisco DNA Center Auth
   :return: the report report view details
    """
    url = DNAC_URL + '/dna/intent/api/v1/data/view-groups/' + group_id + '/views/' + view_id
    header = {'Content-Type': 'application/json', 'X-Auth-Token': dnac_auth}
    response = requests.get(url, headers=header, verify=False)
    report_detailed_views = response.json()
    return report_detailed_views

def get_report_id(report_name: str, view_id: str, group_id: str, dnac_auth: str):
    """
    This function will retrieve the individual report id for the view group id {group_id} and view id {view_id}
   :param report_name: report name string
   :param view_id: report view id
   :param group_id: report group id
   :param dnac_auth: Cisco DNA Center Auth
   :return: the report id of the matching report name
    """
    report_id = 0
    url = DNAC_URL + '/dna/intent/api/v1/data/reports/' +'?' + 'viewGroupId=' + group_id + '&' + 'viewId=' + view_id
    header = {'Content-Type': 'application/json', 'X-Auth-Token': dnac_auth}
    response = requests.get(url, headers=header, verify=False)
    if (response.status_code == requests.codes.ok):
        for report in response.json():
            if report['name'] == report_name:
                report_id = report['reportId']
    return report_id

def create_report(payload: str, dnac_auth: str):
    """
    This function will create a new Client Detail report
   :param payload: request payload
   :param dnac_auth: Cisco DNA Center Auth
   :return: return the API response
    """
    url = DNAC_URL + '/dna/intent/api/v1/data/reports'
    header = {'Content-Type': 'application/json', 'X-Auth-Token': dnac_auth}
    op_res = requests.post(url, headers=header, data=json.dumps(payload), verify=False)
    logging.info("Report create: {0}".format(op_res))
    return op_res

def delete_report(report_id: str, dnac_auth: str):
    """
    This function will delete a schedule report
   :param report_id: reportId to delete
   :param dnac_auth: Cisco DNA Center Auth
   :return: return the API response
    """
    op_res = -1

    if report_id:
        url = DNAC_URL + '/dna/intent/api/v1/data/reports/' + report_id
        header = {'Content-Type': 'application/json', 'X-Auth-Token': dnac_auth}
        op_res = requests.delete(url, headers=header, verify=False)
        logging.info("Report cleanup: {0}".format(op_res))
    else:
        logging.info("Report cleanup skipped.")
    return op_res

def get_report_executions(report_id: str, dnac_auth: str):
    """
    This function will get the report executions info for the {report_id}
    :param report_id: the report id
    :param dnac_auth: Cisco DNA Center Auth
    :return: return the response payload
    """
    url = DNAC_URL + '/dna/intent/api/v1/data/reports/' + report_id + '/executions'
    header = {'Content-Type': 'application/json', 'X-Auth-Token': dnac_auth}
    response = requests.get(url, headers=header, verify=False)
    response_json = response.json()
    return response_json

def get_report_file(report_id, execution_id, dnac_auth):
    """
    This function will return the report content specified by the {report_id} and {execution_id}
    :param report_id: report id
    :param execution_id: execution id
    :param dnac_auth: Cisco DNA Center Auth
    :return: report data
    """
    url = DNAC_URL + '/dna/intent/api/v1/data/reports' + report_id + '/executions/' + execution_id
    header = {'Content-Type': 'application/json', 'X-Auth-Token': dnac_auth}
    response = requests.get(url, headers=header, verify=False)
    report = response.json()
    return report

def export_report_file (report_content: json, filename: str):
    # save the report to a file
    try:
        report = json.dumps(report_content)
        if 'error' in report_content:
            raise ValueError('Report error received')
        with open(filename, 'w') as file:
            file.write(report)
            file.close()
        logging.info("Report saveed to file {0}".format(filename))
    except:
        report_error = report_content['error']
        print('Client report not saved, error received: ', report_error)
        logging.info("Report save to file {0} failed with {1}".format(filename, report_error))

def get_date_range(interval: str):
    REPORT_DATE_TO = datetime.now().replace(tzinfo=timezone.utc, day=1,hour=23,minute=59,second=59) - timedelta(days=1)
    REPORT_DATE_FROM = datetime.now().replace(tzinfo=timezone.utc, day=1,hour=0,minute=0,second=0) - timedelta(days=REPORT_DATE_TO.day)
    #today's date
    today = datetime.now().replace(tzinfo=timezone.utc)
    weekday = today.weekday()

    date_range = {
        "report_date_from": today,
        "report_date_to": today
    }

    if interval == '24hours':
        delta = timedelta(days=1)
        date_range['report_date_to'] = today
        date_range['report_date_from'] = date_range['report_date_to'] - delta
    elif interval == 'week':
        delta = timedelta(days=weekday,weeks=1)
        date_range['report_date_from'] = (today - delta).replace(hour=0,minute=0,second=0)
        date_range['report_date_to'] = (date_range['report_date_from'] + timedelta(weeks=1)).replace(hour=23,minute=59,second=59)
    elif interval == 'month':
        date_range['report_date_to'] = today.replace(day=1,hour=23,minute=59,second=59) - timedelta(days=1)
        date_range['report_date_from'] = today.replace(day=1,hour=0,minute=0,second=0) - timedelta(days=date_range['report_date_to'].day)
    elif interval == '3month':
        date_range['report_date_to'] = today.replace(day=1,hour=23,minute=59,second=59) - timedelta(days=1)
        date_range['report_date_from'] = today.replace(day=1,hour=0,minute=0,second=0) - relativedelta(months=+6)
    else:
        delta = timedelta(days=1)
        date_range['report_date_to'] = (today - delta).replace(hour=23,minute=59,second=59)
        date_range['report_date_from'] = (today - delta).replace(hour=0,minute=0,second=0)

    return date_range


@click.command()
@click.option('--verbose', is_flag=True, default = False, help="Will print verbose messages.")
@click.option(
    '--last', default="day", 
    type=click.Choice(['24hours','day','week','month','3month']),
    help="Collect data for last number of [24hours|day|week|month|3month]. Default is day")
def main(verbose,last):
    """
    This application will create a new Threat Detail Report in DNAC:
    for the Global site
    All Threat Details in the requested interval
    Will check when report execution is completed and save the report to a file
    Index the generated report into Elastic for archiving purposes
    Note: During Indexing, Threat MAC Address will be treated as a UUID
    to avoid Threat duplication. If same MAC Address is encountered, the record will be updated in Elastic
    """
    VERBOSE = verbose

    # logging, debug level, to file {application_run.log}
    logging.basicConfig(
        filename='application_run.log',
        level=logging.DEBUG,
        format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
        datefmt=DATE_PRINT_FORMAT)

    current_time = str(datetime.now().strftime(DATE_PRINT_FORMAT))

    date_range = get_date_range(last)
    REPORT_DATE_FROM = date_range['report_date_from']
    REPORT_DATE_TO = date_range['report_date_to']

    REPORT_NAME = VIEW_NAME +  " {0} ".format(last) + REPORT_DATE_TO.strftime(REPORT_NAME_DATE_FORMAT)

    # get the Cisco DNA Center Auth token
    dnac_auth = get_dnac_jwt_token(DNAC_AUTH)

    #establish connectivity to Elastic cluster
    es_connection = dnacenter_elastic.connect_es(elastic_url=ELASTIC_URL,elastic_user=ELASTIC_USER,elastic_pass=ELASTIC_PASS)
    if VERBOSE:
        print ("Connected to Elastic \nCluster name:\t{0}\nversion:\t{1}\n".format(
            es_connection.info()['name'], 
            es_connection.info()['version']['number']))

    view_group_id = get_report_view_group_id (report_category=REPORT_CATEGORY, dnac_auth=dnac_auth)
    report_view_id = get_report_view_id_by_name (view_name=VIEW_NAME, view_group_id=view_group_id, dnac_auth=dnac_auth)

    if VERBOSE:
        print('\nCreate Report App Run Start, ', current_time)
        print('\nReport name:\n {0}'.format(REPORT_NAME))
        print('\nReport dates:\n{0}\n{1}'.format(REPORT_DATE_FROM.strftime(DATE_PRINT_FORMAT), REPORT_DATE_TO.strftime(DATE_PRINT_FORMAT)))
        print('\nReport Category:', REPORT_CATEGORY)
        print('\nReport View Group Id is:', view_group_id)
        print('\nReport View Name:', VIEW_NAME)
        print('\nReport View Id is:', report_view_id)

    # get the detailed report views
    # this is useful when constructing a new report request and you need to get field names
    #report_detail_view = get_detailed_report_views(report_view_id, view_group_id, dnac_auth)

    # get report id if it exists
    report_id = get_report_id(REPORT_NAME, report_view_id, view_group_id, dnac_auth)

    # clean up previous report with same name, if exists
    delete_report (report_id=report_id, dnac_auth=dnac_auth)

    #es_report_index_mapping = EsReportMapping.Threat_Detail_Mapping.copy()
    es_report_index_mapping = dnacenter_reports.ES_Threat_Detail_Mapping.copy()
    es_report_index_mapping['mappings']['properties']['geojson'] = {"type": "geo_point"}

    # construct new request payload specific to 'thread detail' report params
    #report_request = DnacReportPayload.Threat_Detail_Payload.copy()
    report_request = dnacenter_reports.DNAC_Threat_Detail_Payload.copy()
    # print(json.dumps(es_report_index_mapping))
    report_request['name'] = REPORT_NAME
    report_request['dataCategory'] = REPORT_CATEGORY
    report_request['viewGroupId'] = view_group_id
    report_request['view']['name'] = VIEW_NAME
    report_request['view']['id'] = report_view_id
    report_request['view']['description'] = REPORT_NAME
    # filter constructor which must be augmented to report request payload 'view' dict
    report_request_filter = dnacenter_reports.get_filter_dict(location=[],date_from=REPORT_DATE_FROM, date_to=REPORT_DATE_TO)

    # append the filter to 'view' (note: append, not replace)
    report_request['view'] = {**report_request['view'], **report_request_filter}

    #clock end-to-end report generation in dnac
    dnac_report_timer_start = timer()
    create_report_status = create_report(payload=report_request, dnac_auth=dnac_auth)

    if (create_report_status.status_code == requests.codes.ok):
        if VERBOSE:
            print('\nReport submitted')

        # parsing the response from create new report API
        create_report_json = create_report_status.json()
        report_id = create_report_json['reportId']

        if VERBOSE:
            print('Report id: ', report_id)

        # verify when the report execution starts
        # this app will create a new report, not execute an existing report again
        # due to this there will be always execution count "0" when the report is triggered
        # for a new report, not executed yet

        if VERBOSE:
            print('\nWait for report execution to start')

        start = timer()
        execution_count = 0
        while execution_count == 0:
            time.sleep(1)
            if VERBOSE:
                print('!', end="", flush=True)
            report_details = get_report_executions(report_id, dnac_auth)
            execution_count = report_details['executionCount']
        end=timer()

        if VERBOSE:
            print("\nOperation took: {0} seconds".format(end-start))

        # report execution started
        if VERBOSE:
            print('\n\nReport execution started, wait for process to complete')

        # check when the report is completed
        process_status = None
        start=timer()
        while process_status != 'SUCCESS':
            time.sleep(1)
            if VERBOSE:
                print('!', end="", flush=True)
            report_details = get_report_executions(report_id, dnac_auth)
            execution_info = report_details['executions'][0]
            process_status = execution_info['processStatus']
        end=timer()

        if VERBOSE:
            print("\nOperation took: {0} seconds".format(end-start))

        # execution completed successfully

        if VERBOSE:
            print('\n\nReport execution completed')
        execution_id = report_details['executions'][0]['executionId']

        if VERBOSE:
            print('Report execution id: ', execution_id)

        # download the report
        # call the API to download the report file
        report_content = get_report_file(report_id, execution_id, dnac_auth)
        # print('\nReport content:\n', report_content)

    else:
        if VERBOSE:
            print('\nReport not submitted. \nCode:\t{0}\nStatus:\t{1} '.format(create_report_status.status_code, create_report_status.reason))
        logging.debug('Report not submitted. \nCode:\t{0}\nStatus:\t{1} '.format(create_report_status.status_code, create_report_status.reason))
        sys.exit(1)

    #clock end-to-end report generation in dnac
    dnac_report_timer_end = timer()

    if VERBOSE:
        print('Create Report App Run End')
        print("Operation took: {0} seconds".format(dnac_report_timer_end-dnac_report_timer_start))

    res = dnacenter_elastic.create_index(
        index_name=ELASTIC_INDEX, 
        mapping=es_report_index_mapping, 
        es_client=es_connection)

    # time export operation
    start = timer()
    res = dnacenter_elastic.bulk_index(
        index_name=ELASTIC_INDEX,
        report_content=report_content['rogue_details'],
        unique_hash_key='macAddress', 
        es_client=es_connection,
        SiteHierarchyDelimiter=SITE_HIERARCHY_DELIMITER)
    end=timer()

    if VERBOSE:
        print ("Elastic export completed.{0}".format(res))
        print ("Operation took: {0} seconds".format(end-start))

if __name__ == '__main__':
    main()
