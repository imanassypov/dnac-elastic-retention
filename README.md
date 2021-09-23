[![DEVNET](https://upload.wikimedia.org/wikipedia/en/f/f8/CiscoDevNet2.png)](https://developer.cisco.com)

# DNA Center - Rogue Detail archiving script for long term retention in Elastic

## Features
- Script can be run on a schedule (ie crontab), collect Rogue Detail data from DNAC and upload to Elastic cluster
- Script will automatically create an Elastic Index if it does not exist
- Rogue MAC Address id is treated as a unique identifier when indexing to Elastic to avoid Rogue Entry duplication. Ie if the mac address of the rogue is already indexed, this entry will be updated in Elastic rather than created anew
- Each execution of the script is logged to local file 'application_run.log'
- The script will generate a snapshot of all Locations under 'Global' location hierarchy in DNAC. Further analysis / data slicing can be performed in Elastic/Kibana
- DNAC Report API requires submission of report payload as part of the call. Sample payload structures are included in this repository for reference
- Note: DNAC Report Payload includes 'filter' section, which allows for specification of various filters such as time range, location etc. Location filter supports a maximum of 254 elements, so when creating an API call for a Site Hierarchy element which contains more that 254 elements (ie buildings, floors etc) - report API request must be submitted in batches with 'location' filter populated with up to 254 floor elements
- Elastic Mapping schema used in the script leverages dynamic / runtime fields that calculate hour of day, and day of week to enable heatmap visualizations
- Script logic additionally breaks up the report supplied 'Location' string into individual fields when indexed into Elastic to allow for further per-location filtering (ie Country / City / Building / Floor etc)

### Assumptions
- It is assumed that the script is run automatically at scheduled intervals (ie daily, monthly)
- DNAC with managed Wireless Lan Controller and associated Access Points
- Elastic Stack / Kibana


## Requirements
- Elastic 7.14.1 (as tested)
- Kibana
- Python 3.9.7 (as tested)
- DNAC 2.2.2.3 (as tested)

## References
- The code for this script was forked from Gabi Zapodeanu's repo: 
-- https://github.com/cisco-en-programmability/dnacenter_reports_operations


## Installation
- clone repository to your local machine

```sh
 git clone https://github.com/imanassypov/dnac-elastic-retention.git
```

- copy sample environment.env.sample file and modify to match credentials in your environment
- perform a sample script execution

```sh
python3 dnacenter_archiver.py --verbose --last month
Connected to Elastic
Cluster name:   elastic
version:    7.14.1

Create Report App Run Start,  2021-09-23 11:58:58

Report name:
Threat Detail month 2021-08-31

Report dates:
2021-08-01 00:00:00
2021-08-31 23:59:59

Report Category: Rogue and aWIPS

Report View Group Id is: 97afe5c9-4941-4251-8bf5-0fb643e90841

Report View Name: Threat Detail

Report View Id is: 5057bfff-30bd-4a08-8439-82e4c957d367

Report submitted
Report id:  1ed9fce1-b2dd-47ce-8cf7-4a209c0f3d1a

Wait for report execution to start
!!!!!!!!!!!!!!
Operation took: 19.784386487 seconds

Report execution started, wait for process to complete
!!!!!!!!!!!!!!
Operation took: 20.058992730999996 seconds

Report execution completed
Report execution id:  34a4fb59-177a-4f49-8fa2-e298cb860545
Create Report App Run End
Operation took: 40.706254177 seconds
Elastic export completed.(32, [])
Operation took: 0.3002833649999985 seconds
```

## Supported intervals
- please note that minimum interval supported by DNAC for reporting purposes is 3 hours
- script supports following time intervals

```sh
--last 24hours|day|week|month|3month
```