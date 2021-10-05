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

from datetime import datetime, timezone, timedelta

ES_Threat_Detail_Mapping = {
    "mappings": {
        "properties": {
            "threatLevel": {"type": "keyword"},
            "macAddress": {"type": "keyword"},
            "threatType": {"type": "keyword"},
            "apName": {"type": "keyword"},
            "siteHierarchyName": {"type": "keyword"},
            "country": {"type": "keyword"},
            "province": {"type": "keyword"},
            "city": {"type": "keyword"},
            "branch": {"type": "keyword"},
            "floor": {"type": "keyword"},
            "rssi": {"type": "keyword"},
            "ssid": {"type": "keyword"},
            "vendor": {"type": "keyword"},
            "lastUpdated": {"type": "date"},
            "location": {"type": "geo_point"}
        },
        "runtime": {
            "day_of_week": {
            "type": "keyword",
                "script": {
                    "source": "emit(doc['lastUpdated'].value.dayOfWeekEnum.getDisplayName(TextStyle.FULL, Locale.ROOT))"
                }
            },
            "hour_of_day": {
                "type": "double",
                "script": {
                    "source": "emit(doc['lastUpdated'].value.hourOfDay)"
                }
            }
        }
    }
}

#
DNAC_Threat_Detail_Payload = {
    'name': 'REPORT_NAME',
    'description': '',
    'dataCategory': 'REPORT_CATEGORY',
    'viewGroupId': 'view_group_id',
    'viewGroupVersion': '2.0.0',
    'schedule': {
        'type': 'SCHEDULE_NOW'
    },
    'deliveries': [
        {
            'type': 'DOWNLOAD',
            "default": True
        }
    ],
    'view': {
        'name': 'VIEW_NAME',
        'viewId': 'report_view_id',
        'description': 'REPORT_NAME',
        'fieldGroups': [
            {
                'fieldGroupName': 'REPORT_CATEGORY',
                'fieldGroupDisplayName': 'REPORT_NAME',
                "fields":
                [
                    {
                        "name": "threatLevel",
                        "displayName": "Threat Level"
                    },
                    {
                        "name": "macAddress",
                        "displayName": "Mac Address"
                    },
                    {
                        "name": "threatType",
                        "displayName": "Threat Type"
                    },
                    {
                        "name": "apName",
                        "displayName": "Detecting AP Name"
                    },
                    {
                        "name": "siteHierarchyName",
                        "displayName": "Location"
                    },
                    {
                        "name": "rssi",
                        "displayName": "Latest RSSI (dBm)"
                    },
                    {
                        "name": "ssid",
                        "displayName": "SSID"
                    },
                    {
                        "name": "vendor",
                        "displayName": "Vendor Name"
                    },
                    {
                        "name": "lastUpdated",
                        "displayName": "Last Updated"
                    }
                ]
            }
        ],
        # 'filters': [
        #     {
        #         'name': 'Location',
        #         'displayName': 'Location',
        #         'type': 'MULTI_SELECT_TREE',
        #         'value': []
        #     },
        #     {
        #         'name': 'TimeRange',
        #         'type': 'TIME_RANGE',
        #         'displayName': 'Time Range',
        #         'value': {
        #             'timeRangeOption': 'CUSTOM',
        #             'startDateTime': 'REPORT_DATE_FROM.timestamp() * MILLISECONDS',
        #             'endDateTime': 'REPORT_DATE_TO.timestamp() * MILLISECONDS'
        #         }
        #     }
        # ],
        'format': {
            'name': 'JSON',
            'formatType': 'JSON',
            'default': False
        }
    }
}

def get_filter_dict (location: list, date_from: datetime, date_to: datetime):
    dict_filters = {
        'filters': [
                {
                    'name': 'Location',
                    'displayName': 'Location',
                    'type': 'MULTI_SELECT_TREE',
                    'value': location
                },
                {
                    'name': 'TimeRange',
                    'type': 'TIME_RANGE',
                    'displayName': 'Time Range',
                    'value': {
                        'timeRangeOption': 'CUSTOM',
                        'startDateTime': date_from.timestamp() * 1000,
                        'endDateTime': date_to.timestamp() * 1000
                    }
                }
            ]
        }
    return dict_filters


# Configure at least one email account to enable Watcher to send email.
# For more information, refer to Configuring email accounts: https://www.elastic.co/guide/en/elasticsearch/reference/7.15/actions-email.html#configuring-email

# API PUT _watcher/watch/<report name>
Create_Watcher_Report= {
  "trigger": {
    "schedule": {
      "interval": "1d"  # Set Interval
    }
  },
  "actions" : {
    "email_admin" : {
      "email": {
        "to": "",   # Receiver email address
        "subject": "",  # Subject
        "attachments": {
          "attachment.pdf": {    # name of attachment/report
            "reporting": {
              "url": "",    # Created POST URL from elastic page to be exported
              "retries":40,
              "interval":"15s",
              "auth":{
                "basic":{
                  "username":"",    # Elastic user
                  "password":""     # Elastic password
                }
              }
            }
          }
        }
      }
    }
  }
}