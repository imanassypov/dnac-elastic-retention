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
__author__ = "Andrew Dunsmoor, Technical Solutions Specialist"
__email__ = "adunsmoo@cisco.com"
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
    #ELASTIC_LOCAL = env_dict['ELASTIC_LOCAL']
except Exception as e:
    print(e)
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

#Elastic parameters
ELASTIC_INDEX = 'igor_dnac_rogue_threat_detail'
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
   :return: list of sites, each of which is a dictionary
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
                    # Due to a bug in DNA-C where floors have location [0,0] we need to find parent
                    parentId = site["parentId"]

                    # Once we have found the parent (building of the floor), search for it and return location
                    for building in sites.copy():
                        if building["id"] == parentId:
                            if building['longitude'] and building['latitude']:
                                mypoint = [round(float(building['longitude']), 2), round(float(building['latitude']), 2)]
                                return mypoint
    # If nothing found, return a blank point
    return []
    # return [-79.347015, 43.651070] # For debugging, return Toronto

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


def create_pdf_report(subject: str, to: str, filename: str, es_client, interval: str):
    """
    Creates a watcher in elastic with an action to send an email containing a pdf report with the specifications listed.
    Ex:     res = create_pdf_report("test_reportname", "test_subject", "'Testing Sender <test@cisco.com>'", "test_filename", es_connection)
    @param subject: Subject of the email
    @param to: receiver's email address
    @param filename: name of the file
    @param es_client: Client connection object dnacenter_elastic.connect_es()
    @param interval: time interfval in format of integer+minutes/hours/days specified with: <number><m/h/d>
    @return: http response body of the put request
    Detailed guide to configuration of automated reports here: # https://www.elastic.co/guide/en/kibana/current/automating-report-generation.html
    """

    params = {"active": "true"}

    payload = {
        "trigger": {
            "schedule": {
                # "interval": "1d"  # Set Interval
                "interval": interval  # Set Interval, format: <number><m/h/d>
            }
        },
        "actions": {
            "email_admin": {
                "email": {
                    "to": to,  # Receiver email address
                    "subject": subject,  # Subject
                    "attachments": {
                        filename: {  # name of attachment/report
                            "reporting": {
                                "url": f"{ELASTIC_LOCAL}api/reporting/generate/printablePdf?jobParams=%28browserTimezone%3AUTC%2Clayout%3A%28dimensions%3A%28height%3A1688%2Cwidth%3A1515%29%2Cid%3Apreserve_layout%2Cselectors%3A%28itemsCountAttribute%3Adata-shared-items-count%2CrenderComplete%3A%5Bdata-shared-item%5D%2Cscreenshot%3A%5Bdata-shared-items-container%5D%2CtimefilterDurationAttribute%3Adata-shared-timefilter-duration%29%29%2CobjectType%3Adashboard%2CrelativeUrls%3A%21%28%27%2Fapp%2Fdashboards%23%2Fview%2Fe1b1c6f0-1a6b-11ec-88b6-4d50bc2aa6a9%3F_g%3D%28filters%3A%21%21%28%29%2Cquery%3A%28language%3Akuery%2Cquery%3A%21%27%21%27%29%2CrefreshInterval%3A%28pause%3A%21%21f%2Cvalue%3A10000%29%2Ctime%3A%28from%3Anow-16d%2Cto%3Anow%29%29%26_a%3D%28description%3A%21%27DNAC%2520Exported%2520Rogue%2520Detail%21%27%2Cfilters%3A%21%21%28%29%2CfullScreenMode%3A%21%21f%2Coptions%3A%28hidePanelTitles%3A%21%21f%2CsyncColors%3A%21%21f%2CuseMargins%3A%21%21t%29%2Cpanels%3A%21%21%28%28embeddableConfig%3A%28enhancements%3A%28%29%2Csort%3A%21%21%28%21%21%28macAddress%2Cdesc%29%2C%21%21%28threatLevel%2Cdesc%29%2C%21%21%28siteHierarchyName%2Cdesc%29%2C%21%21%28threatType%2Cdesc%29%29%29%2CgridData%3A%28h%3A15%2Ci%3A%21%27640c5ff7-d916-4318-a8fa-1ddeccfe6877%21%27%2Cw%3A32%2Cx%3A0%2Cy%3A0%29%2Cid%3Aa2e755f0-1a6d-11ec-88b6-4d50bc2aa6a9%2CpanelIndex%3A%21%27640c5ff7-d916-4318-a8fa-1ddeccfe6877%21%27%2Ctype%3Asearch%2Cversion%3A%21%277.14.1%21%27%29%2C%28embeddableConfig%3A%28enhancements%3A%28%29%2ChidePanelTitles%3A%21%21f%2CsavedVis%3A%28data%3A%28aggs%3A%21%21%28%28enabled%3A%21%21t%2Cid%3A%21%271%21%27%2Cparams%3A%28%29%2Cschema%3Ametric%2Ctype%3Acount%29%2C%28enabled%3A%21%21t%2Cid%3A%21%272%21%27%2Cparams%3A%28customLabel%3A%21%27%21%27%2Cfield%3AthreatLevel%2CmissingBucket%3A%21%21f%2CmissingBucketLabel%3AMissing%2Corder%3Adesc%2CorderBy%3A%21%271%21%27%2CotherBucket%3A%21%21t%2CotherBucketLabel%3AOther%2Csize%3A5%29%2Cschema%3Asegment%2Ctype%3Aterms%29%29%2CsavedSearchId%3Aa2e755f0-1a6d-11ec-88b6-4d50bc2aa6a9%2CsearchSource%3A%28filter%3A%21%21%28%29%2Cquery%3A%28language%3Akuery%2Cquery%3A%21%27%21%27%29%29%29%2Cdescription%3A%21%27%21%27%2Cparams%3A%28maxFontSize%3A72%2CminFontSize%3A18%2Corientation%3Asingle%2Cpalette%3A%28name%3Adefault%2Ctype%3Apalette%29%2Cscale%3Alinear%2CshowLabel%3A%21%21t%29%2Ctitle%3A%21%27%21%27%2Ctype%3Atagcloud%2CuiState%3A%28%29%29%29%2CgridData%3A%28h%3A15%2Ci%3A%21%275d537f88-0cf9-4548-abfa-951344be3b45%21%27%2Cw%3A10%2Cx%3A0%2Cy%3A15%29%2CpanelIndex%3A%21%275d537f88-0cf9-4548-abfa-951344be3b45%21%27%2Ctitle%3A%21%27Rogue%2520Threat%2520Levels%21%27%2Ctype%3Avisualization%2Cversion%3A%21%277.14.1%21%27%29%2C%28embeddableConfig%3A%28enhancements%3A%28%29%2ChidePanelTitles%3A%21%21f%2CsavedVis%3A%28data%3A%28aggs%3A%21%21%28%28enabled%3A%21%21t%2Cid%3A%21%271%21%27%2Cparams%3A%28%29%2Cschema%3Ametric%2Ctype%3Acount%29%2C%28enabled%3A%21%21t%2Cid%3A%21%272%21%27%2Cparams%3A%28field%3Avendor%2CmissingBucket%3A%21%21f%2CmissingBucketLabel%3AMissing%2Corder%3Adesc%2CorderBy%3A%21%271%21%27%2CotherBucket%3A%21%21f%2CotherBucketLabel%3AOther%2Csize%3A15%29%2Cschema%3Asegment%2Ctype%3Aterms%29%29%2CsavedSearchId%3Aa2e755f0-1a6d-11ec-88b6-4d50bc2aa6a9%2CsearchSource%3A%28filter%3A%21%21%28%29%2Cquery%3A%28language%3Akuery%2Cquery%3A%21%27%21%27%29%29%29%2Cdescription%3A%21%27%21%27%2Cparams%3A%28maxFontSize%3A26%2CminFontSize%3A6%2Corientation%3Asingle%2Cpalette%3A%28name%3Adefault%2Ctype%3Apalette%29%2Cscale%3Alinear%2CshowLabel%3A%21%21t%29%2Ctitle%3A%21%27%21%27%2Ctype%3Atagcloud%2CuiState%3A%28%29%29%29%2CgridData%3A%28h%3A15%2Ci%3Af2280c78-ecc1-4e44-afd3-121bedfb8e9d%2Cw%3A12%2Cx%3A20%2Cy%3A15%29%2CpanelIndex%3Af2280c78-ecc1-4e44-afd3-121bedfb8e9d%2Ctitle%3A%21%27Rogue%2520Vendors%21%27%2Ctype%3Avisualization%2Cversion%3A%21%277.14.1%21%27%29%2C%28embeddableConfig%3A%28enhancements%3A%28%29%2ChidePanelTitles%3A%21%21f%2CsavedVis%3A%28data%3A%28aggs%3A%21%21%28%28enabled%3A%21%21t%2Cid%3A%21%271%21%27%2Cparams%3A%28%29%2Cschema%3Ametric%2Ctype%3Acount%29%2C%28enabled%3A%21%21t%2Cid%3A%21%272%21%27%2Cparams%3A%28field%3AthreatType%2CmissingBucket%3A%21%21f%2CmissingBucketLabel%3AMissing%2Corder%3Adesc%2CorderBy%3A%21%271%21%27%2CotherBucket%3A%21%21f%2CotherBucketLabel%3AOther%2Csize%3A5%29%2Cschema%3Asegment%2Ctype%3Aterms%29%29%2CsavedSearchId%3Aa2e755f0-1a6d-11ec-88b6-4d50bc2aa6a9%2CsearchSource%3A%28filter%3A%21%21%28%29%2Cquery%3A%28language%3Akuery%2Cquery%3A%21%27%21%27%29%29%29%2Cdescription%3A%21%27%21%27%2Cparams%3A%28maxFontSize%3A72%2CminFontSize%3A18%2Corientation%3Asingle%2Cpalette%3A%28name%3Adefault%2Ctype%3Apalette%29%2Cscale%3Alinear%2CshowLabel%3A%21%21t%29%2Ctitle%3A%21%27%21%27%2Ctype%3Atagcloud%2CuiState%3A%28%29%29%29%2CgridData%3A%28h%3A15%2Ci%3A%21%27658e4e45-d673-47ad-9521-94d099c73f6f%21%27%2Cw%3A10%2Cx%3A10%2Cy%3A15%29%2CpanelIndex%3A%21%27658e4e45-d673-47ad-9521-94d099c73f6f%21%27%2Ctitle%3A%21%27Rogue%2520Threat%2520Types%21%27%2Ctype%3Avisualization%2Cversion%3A%21%277.14.1%21%27%29%2C%28embeddableConfig%3A%28enhancements%3A%28%29%2ChidePanelTitles%3A%21%21f%2CsavedVis%3A%28data%3A%28aggs%3A%21%21%28%28enabled%3A%21%21t%2Cid%3A%21%271%21%27%2Cparams%3A%28%29%2Cschema%3Ametric%2Ctype%3Acount%29%2C%28enabled%3A%21%21t%2Cid%3A%21%272%21%27%2Cparams%3A%28extended_bounds%3A%28max%3A%21%27%21%27%2Cmin%3A%21%27%21%27%29%2Cfield%3Ahour_of_day%2Chas_extended_bounds%3A%21%21f%2Cinterval%3A1%2Cmin_doc_count%3A%21%21f%2Cused_interval%3A1%29%2Cschema%3Asegment%2Ctype%3Ahistogram%29%2C%28enabled%3A%21%21t%2Cid%3A%21%273%21%27%2Cparams%3A%28field%3AthreatLevel%2CmissingBucket%3A%21%21f%2CmissingBucketLabel%3AMissing%2Corder%3Adesc%2CorderBy%3A%21%271%21%27%2CotherBucket%3A%21%21f%2CotherBucketLabel%3AOther%2Csize%3A5%29%2Cschema%3Agroup%2Ctype%3Aterms%29%29%2CsavedSearchId%3Aa2e755f0-1a6d-11ec-88b6-4d50bc2aa6a9%2CsearchSource%3A%28filter%3A%21%21%28%29%2Cquery%3A%28language%3Akuery%2Cquery%3A%21%27%21%27%29%29%29%2Cdescription%3A%21%27%21%27%2Cparams%3A%28addLegend%3A%21%21t%2CaddTooltip%3A%21%21t%2CcolorSchema%3AGreens%2CcolorsNumber%3A4%2CcolorsRange%3A%21%21%28%29%2CenableHover%3A%21%21f%2CinvertColors%3A%21%21f%2ClegendPosition%3Aright%2CpercentageMode%3A%21%21f%2CsetColorRange%3A%21%21f%2Ctimes%3A%21%21%28%29%2Ctype%3Aheatmap%2CvalueAxes%3A%21%21%28%28id%3AValueAxis-1%2Clabels%3A%28color%3Ablack%2CoverwriteColor%3A%21%21f%2Crotate%3A0%2Cshow%3A%21%21f%29%2Cscale%3A%28defaultYExtents%3A%21%21f%2Ctype%3Alinear%29%2Cshow%3A%21%21f%2Ctype%3Avalue%29%29%29%2Ctitle%3A%21%27%21%27%2Ctype%3Aheatmap%2CuiState%3A%28vis%3A%28defaultColors%3A%28%21%270%2520-%252010%21%27%3A%21%27rgb%28247%2C252%2C245%29%21%27%2C%21%2710%2520-%252020%21%27%3A%21%27rgb%28198%2C232%2C191%29%21%27%2C%21%2720%2520-%252030%21%27%3A%21%27rgb%28114%2C195%2C120%29%21%27%2C%21%2730%2520-%252040%21%27%3A%21%27rgb%2834%2C139%2C69%29%21%27%29%29%29%29%2Cvis%3A%21%21n%29%2CgridData%3A%28h%3A15%2Ci%3A%21%2706df2ff6-0263-4a0a-8bf9-aa94de1c3788%21%27%2Cw%3A32%2Cx%3A0%2Cy%3A30%29%2CpanelIndex%3A%21%2706df2ff6-0263-4a0a-8bf9-aa94de1c3788%21%27%2Ctitle%3A%21%27Hourly%2520Threat%2520Level%2520Distribtuion%2520%21%27%2Ctype%3Avisualization%2Cversion%3A%21%277.14.1%21%27%29%2C%28embeddableConfig%3A%28attributes%3A%28description%3A%21%27%21%27%2ClayerListJSON%3A%21%27%255B%257B%2522sourceDescriptor%2522%3A%257B%2522type%2522%3A%2522EMS_TMS%2522%2C%2522isAutoSelect%2522%3Atrue%257D%2C%2522id%2522%3A%25221c489b10-a9de-4de2-9a56-a8bd7e2727fa%2522%2C%2522label%2522%3Anull%2C%2522minZoom%2522%3A0%2C%2522maxZoom%2522%3A24%2C%2522alpha%2522%3A1%2C%2522visible%2522%3Atrue%2C%2522style%2522%3A%257B%2522type%2522%3A%2522TILE%2522%257D%2C%2522includeInFitToBounds%2522%3Atrue%2C%2522type%2522%3A%2522VECTOR_TILE%2522%257D%2C%257B%2522sourceDescriptor%2522%3A%257B%2522indexPatternId%2522%3A%25223f215d20-1a5b-11ec-88b6-4d50bc2aa6a9%2522%2C%2522geoField%2522%3A%2522location%2522%2C%2522requestType%2522%3A%2522point%2522%2C%2522id%2522%3A%2522a63267c5-4b44-4289-a9a3-05bea6b7824f%2522%2C%2522type%2522%3A%2522ES_GEO_GRID%2522%2C%2522applyGlobalQuery%2522%3Atrue%2C%2522applyGlobalTime%2522%3Atrue%2C%2522metrics%2522%3A%255B%257B%2522type%2522%3A%2522count%2522%257D%255D%2C%2522resolution%2522%3A%2522COARSE%2522%257D%2C%2522style%2522%3A%257B%2522type%2522%3A%2522VECTOR%2522%2C%2522properties%2522%3A%257B%2522icon%2522%3A%257B%2522type%2522%3A%2522STATIC%2522%2C%2522options%2522%3A%257B%2522value%2522%3A%2522marker%2522%257D%257D%2C%2522fillColor%2522%3A%257B%2522type%2522%3A%2522DYNAMIC%2522%2C%2522options%2522%3A%257B%2522color%2522%3A%2522Blues%2522%2C%2522colorCategory%2522%3A%2522palette_0%2522%2C%2522field%2522%3A%257B%2522name%2522%3A%2522doc_count%2522%2C%2522origin%2522%3A%2522source%2522%257D%2C%2522fieldMetaOptions%2522%3A%257B%2522isEnabled%2522%3Atrue%2C%2522sigma%2522%3A3%257D%2C%2522type%2522%3A%2522ORDINAL%2522%257D%257D%2C%2522lineColor%2522%3A%257B%2522type%2522%3A%2522STATIC%2522%2C%2522options%2522%3A%257B%2522color%2522%3A%2522%2523FFF%2522%257D%257D%2C%2522lineWidth%2522%3A%257B%2522type%2522%3A%2522STATIC%2522%2C%2522options%2522%3A%257B%2522size%2522%3A0%257D%257D%2C%2522iconSize%2522%3A%257B%2522type%2522%3A%2522DYNAMIC%2522%2C%2522options%2522%3A%257B%2522minSize%2522%3A7%2C%2522maxSize%2522%3A32%2C%2522field%2522%3A%257B%2522name%2522%3A%2522doc_count%2522%2C%2522origin%2522%3A%2522source%2522%257D%2C%2522fieldMetaOptions%2522%3A%257B%2522isEnabled%2522%3Atrue%2C%2522sigma%2522%3A3%257D%257D%257D%2C%2522iconOrientation%2522%3A%257B%2522type%2522%3A%2522STATIC%2522%2C%2522options%2522%3A%257B%2522orientation%2522%3A0%257D%257D%2C%2522labelText%2522%3A%257B%2522type%2522%3A%2522DYNAMIC%2522%2C%2522options%2522%3A%257B%2522field%2522%3A%257B%2522name%2522%3A%2522doc_count%2522%2C%2522origin%2522%3A%2522source%2522%257D%257D%257D%2C%2522labelColor%2522%3A%257B%2522type%2522%3A%2522STATIC%2522%2C%2522options%2522%3A%257B%2522color%2522%3A%2522%2523000000%2522%257D%257D%2C%2522labelSize%2522%3A%257B%2522type%2522%3A%2522STATIC%2522%2C%2522options%2522%3A%257B%2522size%2522%3A14%257D%257D%2C%2522labelBorderColor%2522%3A%257B%2522type%2522%3A%2522STATIC%2522%2C%2522options%2522%3A%257B%2522color%2522%3A%2522%2523FFFFFF%2522%257D%257D%2C%2522symbolizeAs%2522%3A%257B%2522options%2522%3A%257B%2522value%2522%3A%2522circle%2522%257D%257D%2C%2522labelBorderSize%2522%3A%257B%2522options%2522%3A%257B%2522size%2522%3A%2522SMALL%2522%257D%257D%257D%2C%2522isTimeAware%2522%3Atrue%257D%2C%2522id%2522%3A%2522604468c3-276b-4eb0-9095-2bed698a5507%2522%2C%2522label%2522%3Anull%2C%2522minZoom%2522%3A0%2C%2522maxZoom%2522%3A24%2C%2522alpha%2522%3A0.75%2C%2522visible%2522%3Atrue%2C%2522includeInFitToBounds%2522%3Atrue%2C%2522type%2522%3A%2522VECTOR%2522%2C%2522joins%2522%3A%255B%255D%257D%255D%21%27%2CmapStateJSON%3A%21%27%257B%2522zoom%2522%3A1.43%2C%2522center%2522%3A%257B%2522lon%2522%3A-45.03374%2C%2522lat%2522%3A37.66732%257D%2C%2522timeFilters%2522%3A%257B%2522from%2522%3A%2522now-24h%2522%2C%2522to%2522%3A%2522now%2522%257D%2C%2522refreshConfig%2522%3A%257B%2522isPaused%2522%3Atrue%2C%2522interval%2522%3A0%257D%2C%2522query%2522%3A%257B%2522query%2522%3A%2522%2522%2C%2522language%2522%3A%2522kuery%2522%257D%2C%2522filters%2522%3A%255B%255D%2C%2522settings%2522%3A%257B%2522autoFitToDataBounds%2522%3Afalse%2C%2522backgroundColor%2522%3A%2522%2523ffffff%2522%2C%2522disableInteractive%2522%3Afalse%2C%2522disableTooltipControl%2522%3Afalse%2C%2522hideToolbarOverlay%2522%3Afalse%2C%2522hideLayerControl%2522%3Afalse%2C%2522hideViewControl%2522%3Afalse%2C%2522initialLocation%2522%3A%2522LAST_SAVED_LOCATION%2522%2C%2522fixedLocation%2522%3A%257B%2522lat%2522%3A0%2C%2522lon%2522%3A0%2C%2522zoom%2522%3A2%257D%2C%2522browserLocation%2522%3A%257B%2522zoom%2522%3A2%257D%2C%2522maxZoom%2522%3A24%2C%2522minZoom%2522%3A0%2C%2522showScaleControl%2522%3Afalse%2C%2522showSpatialFilters%2522%3Atrue%2C%2522showTimesliderToggleButton%2522%3Atrue%2C%2522spatialFiltersAlpa%2522%3A0.3%2C%2522spatialFiltersFillColor%2522%3A%2522%2523DA8B45%2522%2C%2522spatialFiltersLineColor%2522%3A%2522%2523DA8B45%2522%257D%257D%21%27%2Creferences%3A%21%21%28%29%2Ctitle%3A%21%27Threat%2520Detail%2520Map%21%27%2CuiStateJSON%3A%21%27%257B%2522isLayerTOCOpen%2522%3Atrue%2C%2522openTOCDetails%2522%3A%255B%255D%257D%21%27%29%2Cenhancements%3A%28%29%2ChiddenLayers%3A%21%21%28%29%2CisLayerTOCOpen%3A%21%21f%2CmapBuffer%3A%28maxLat%3A43.64055%2CmaxLon%3A-79.37897%2CminLat%3A43.63955%2CminLon%3A-79.38103%29%2CmapCenter%3A%28lat%3A43.63993%2Clon%3A-79.3799%2Czoom%3A18.17%29%2CopenTOCDetails%3A%21%21%28%29%29%2CgridData%3A%28h%3A15%2Ci%3A%21%27659dc21e-8276-43cf-8022-9c547c0b1c1e%21%27%2Cw%3A24%2Cx%3A0%2Cy%3A45%29%2CpanelIndex%3A%21%27659dc21e-8276-43cf-8022-9c547c0b1c1e%21%27%2Ctype%3Amap%2Cversion%3A%21%277.14.1%21%27%29%29%2Cquery%3A%28language%3Akuery%2Cquery%3A%21%27%21%27%29%2Ctags%3A%21%21%28%29%2CtimeRestore%3A%21%21f%2Ctitle%3A%21%27Rogue%2520and%2520aWIPS%2520-%2520Rogue%2520Detail%21%27%2CviewMode%3Aview%29%27%29%2Ctitle%3A%27Rogue%20and%20aWIPS%20-%20Rogue%20Detail%27%29",
                                "retries": 40,
                                "interval": "15s",
                                "auth": {
                                    "basic": {
                                        "username": ELASTIC_USER, # Elastic user
                                        "password": ELASTIC_PASS  # Elastic password
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    watcher_client = WatcherClient(es_client)
    resp = watcher_client.put_watch(id='test_watch_id4', body=payload, params=params)
    return resp

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
    REPORT_NAME = f"{VIEW_NAME} {last} {REPORT_DATE_FROM.strftime(REPORT_NAME_DATE_FORMAT)} to {REPORT_DATE_TO.strftime(REPORT_NAME_DATE_FORMAT)}"

    # create index name
    index_name = f"{ELASTIC_INDEX}_{last}_{REPORT_DATE_FROM.strftime(REPORT_NAME_DATE_FORMAT)}_to_{REPORT_DATE_TO.strftime(REPORT_NAME_DATE_FORMAT)}"

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
        # index_name=ELASTIC_INDEX,
        index_name=index_name,
        mapping=es_report_index_mapping,
        es_client=es_connection)

    # time export operation
    start = timer()
    res = dnacenter_elastic.bulk_index(
        # index_name=ELASTIC_INDEX,
        index_name = index_name,
        report_content=report_content['rogue_details'],
        unique_hash_key='macAddress',
        es_client=es_connection,
        SiteHierarchyDelimiter=SITE_HIERARCHY_DELIMITER)
    end=timer()

    if VERBOSE:
        print ("Elastic export completed.{0}".format(res))
        print ("Operation took: {0} seconds".format(end-start))

if __name__ == '__main__':
    # main(sys.argv[0], sys.argv[1])
    main()