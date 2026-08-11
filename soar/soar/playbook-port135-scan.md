# SOAR Playbook - Port 135 Scan Response

## Purpose

Automate the initial response when Splunk detects repeated Suricata alerts related to suspicious Port 135 activity.

## Trigger

Splunk alert: **Port 135 Scan Detection**

Trigger condition:

* Suricata signature = `ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection`
* Alert count >= 100

## Input Fields

* src_ip
* dest_ip
* dest_port
* count
* alert_time

## Playbook Workflow

### Step 1 - Create Case

Create a SOAR case titled:

`Suspicious Port 135 activity detected from <src_ip>`

Set:

* Severity: Medium
* Label: network_scan
* Owner: SOC Tier 1

### Step 2 - Enrich Source IP

Actions:

* Resolve hostname
* Retrieve asset details
* Collect recent network activity

### Step 3 - Enrich Destination IP

Actions:

* Resolve hostname
* Retrieve asset details
* Identify exposed services on port 135

### Step 4 - Threat Intelligence

Actions:

* Check IP reputation for source IP
* Check geolocation and ASN
* Search internal threat intelligence notes

### Step 5 - Analyst Notification

Send notification containing:

* Source IP
* Destination IP
* Destination Port
* Alert count
* Link to Splunk search
* Link to SOAR case

### Step 6 - Recommended Analyst Tasks

* Review Windows RPC/DCOM exposure on the destination host.
* Review firewall logs between the two systems.
* Check for additional lateral movement indicators.
* Validate whether the communication is expected.

### Step 7 - Containment Guidance

If the activity is unauthorized:

* Isolate the source host.
* Block unnecessary port 135 communication.
* Initiate malware and endpoint investigation.

### Step 8 - Closure Criteria

Close the case when:

* Root cause is identified,
* Communication is confirmed legitimate or remediated,
* No additional suspicious Port 135 activity is observed.

## Example Event

| Field     | Value      |
| --------- | ---------- |
| src_ip    | 10.0.1.1   |
| dest_ip   | 10.0.1.100 |
| dest_port | 135        |
| count     | 5330       |

## Expected Outcome

The playbook automatically creates a case, enriches the involved assets, performs reputation checks, notifies the SOC analyst, and provides containment guidance for suspicious Port 135 activity.

## Author

Shrikant Raut
