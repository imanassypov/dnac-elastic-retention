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

__author__ = "Igor Manassypov, Systems Architect"
__email__ = "imanassy@cisco.com"
__version__ = "0.1.0"
__copyright__ = "Copyright (c) 2021 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

import logging
import json
import os
import uuid

from elasticsearch import Elasticsearch 
from elasticsearch import helpers

from dnacenter_archiver import get_sites_coordinates, get_site_geojson, DNAC_AUTH, get_dnac_jwt_token


def connect_es (elastic_url: str, elastic_user: str, elastic_pass: str):
    """
    Create connection object to elastic search
    :param elastic_url: url for elastic server
    :param elastic_user: elastic user
    :param elastic_pass: elastic password
    returns result of create operation, or OK(0)
    """
    es_client = Elasticsearch(
            elastic_url,
            http_auth=(elastic_user,elastic_pass)
            )
    logging.info("Connecting to ES:{0}".format(es_client.ping()))
    if not es_client.ping():
        raise ValueError("Connection to Elastic {0} failed".format(elastic_url))
        logging.debug("Connection to Elastic {0} failed".format(elastic_url))
    else:
        logging.info("Connected to Elastic \nCluster name:\t{0}\nversion:\t{1}\n".format(
            es_client.info()['name'], 
            es_client.info()['version']['number']))
    return es_client

def create_index(index_name: str, mapping: dict, es_client: Elasticsearch):
    """
    Create an ES index.
    :param index_name: Name of the index.
    :param mapping: Mapping of the index
    returns result of create operation, or OK(0)
    """
    res = 0

    if not es_client.indices.exists(index_name):
        logging.info("Creating index {0} with the following schema: {1}".format(index_name, {json.dumps(mapping, indent=2)}))
        res = es_client.indices.create(index=index_name, body=mapping)
        logging.info("Creating index result: {0}".format(res))
    else:
        logging.info("Index {0} exists. Skipping create index".format(index_name))
    return res

def doc_count(es_client: Elasticsearch, index: str):
    """
    Get number of records in the index
    returns integer number of records (documents)
    """
    record_count = es_client.count(index=index)['count']
    return record_count


def tokenize_location(siteHieararchyName: str, delimeter: str, sites: list):
    """
    Create a dict location identifier from string
    return tokenized dictionary mapping to expected keys in customer site hierarchy
    """
    hierarchy_template = ['global','country','province','city','branch','floor']
    #hierarchy_template = ['country','province','branch','floor']

    loc = siteHieararchyName.split(delimeter)

    #truncate to available hierarchy mapping elements (n from the tail end of list)
    hierarchy_elements = hierarchy_template[-len(loc):]

    loc_dict = {}

    for i, e in enumerate(loc):
        loc_dict[hierarchy_elements[i]] = e

    loc_dict['geojson'] = get_site_geojson(siteHieararchyName, sites)

    # print(json.dumps(loc_dict))

    return loc_dict

def merge_dict(dict1: dict, dict2: dict):
    res = {**dict1, **dict2}
    return res

def index(index_name: str, report_content: dict, key: str, unique_hash_key: str, es_client: Elasticsearch, SiteHierarchyDelimiter: str):
    """
    Upload report contents to Elastic index
    Will be leveraging deterministic UUID calculation as input to the index function to ensure records containing the same MAC address are updated
    as opposed to duplicated
    returns number of new records indexed (vs updated records)
    :param report_content: DNAC formatted json report payload
    :param key: section of report data payload
    :param unique_hash_key: field in the report that uniquely identifies a record. Will be used to ensure duplicate records are not indexed but rather used as an update
    """
    initial_doc_count = doc_count(es_client=es_client, index=index_name)

    logging.info("Starting to index {0} documents. Total records {1}. Hashing on key {2}".format(len(report_content[key]), initial_doc_count, unique_hash_key))

    op_res = {
        'created': 0,
        'updated': 0,
        'failed': 0,
        'total': initial_doc_count
    }

    # Get Sites to be able to parse out GeoJson for events
    dnac_auth = get_dnac_jwt_token(DNAC_AUTH)
    sites = get_sites_coordinates(dnac_auth)

    for doc in report_content[key]:
        #calculate unique id field such that if script is run multiple times over same 
        #dataset the values are updated instead of duplicated
        unique_mac_id = str(uuid.uuid5(uuid.NAMESPACE_URL,doc[unique_hash_key]))

        doc = merge_dict(
            dict1 = doc, 
            dict2 = tokenize_location(
                siteHieararchyName=doc['siteHierarchyName'],
                delimeter=SiteHierarchyDelimiter,
                sites=sites))

        res = es_client.index(
            index=index_name,
            body=doc,
            id=unique_mac_id)

        if res['result'] == 'updated':
            op_res['updated'] += 1
        elif res['result'] == 'created':
            op_res['created'] += 1
        else:
            op_res['failed'] += 1

    es_client.indices.refresh(index=index_name)
    op_res['total'] = doc_count(es_client,index_name)

    return op_res

def bulk_index(index_name: str, report_content: dict, unique_hash_key: str, es_client: Elasticsearch, SiteHierarchyDelimiter: str):
    initial_doc_count = doc_count(es_client=es_client, index=index_name)
    logging.info("Starting to bulk index {0} documents. Total records {1}. Hashing on key {2}".format(len(report_content), initial_doc_count, unique_hash_key))

    actions = []


    # Get Sites to be able to parse out GeoJson for events
    dnac_auth = get_dnac_jwt_token(DNAC_AUTH)
    sites = get_sites_coordinates(dnac_auth)


    for doc in report_content:
        #uuid returns a class
        #so need to cast it to a string
        _id = str(uuid.uuid5(uuid.NAMESPACE_URL,doc[unique_hash_key]))
        doc["_id"] = _id
        doc["_index"] = index_name
        doc = merge_dict(
            dict1 = doc, 
            dict2 = tokenize_location(
                siteHieararchyName=doc['siteHierarchyName'],
                delimeter=SiteHierarchyDelimiter,
                sites=sites))
        actions += [doc]

    try:
        op_res = helpers.bulk(
            es_client, 
            actions,
            chunk_size = 1000,
            request_timeout = 200)
        print ("Bulk Export result:", op_res)
        logging.debug("Elastic bulk export completed: {0}".format(op_res))
    except Exception as e:
        logging.debug("Elastic bulk export failed: {0}".format(e))

    return op_res