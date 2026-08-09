# SOAR Playbook - Local Authentication Anomaly Response

## Purpose

Automate the initial response when a Splunk alert detects repeated failed Windows logons from the same host and user account.

## Trigger

Splunk alert: **Brute Force / Local Authentication Anomaly Detection**

Trigger condition:

* EventCode = 4625
* Failed logons >= 100
* Same host, user, and source IP combination

## Input Fields

* host
* user
* src_ip
* count
* alert_time

## Playbook Workflow

### Step 1 - Create Case

Create a SOAR case titled:

`Repeated failed logons detected on <host>`

Set:

* Severity: Medium
* Label: authentication
* Owner: SOC Tier 1

### Step 2 - Enrich Host

Actions:

* Resolve hostname
* Retrieve asset details
* Collect recent Windows logon events

### Step 3 - Enrich User

Actions:

* Query directory information (AD/LDAP)
* Retrieve account status
* Check recent password change timestamp

### Step 4 - Validate Source IP

If `src_ip = 127.0.0.1`:

* Tag event as `local_authentication_anomaly`
* Skip external IP reputation lookup

Else:

* Perform threat-intelligence reputation lookup
* Check geolocation and ASN

### Step 5 - Analyst Notification

Send notification to SOC channel/email containing:

* Host
* User
* Source IP
* Failed logon count
* Link to Splunk search
* Link to SOAR case

### Step 6 - Recommended Analyst Tasks

* Review scheduled tasks on the host.
* Review services using stored credentials.
* Review application logs for authentication failures.
* Verify whether the user recently changed passwords.

### Step 7 - Closure Criteria

Close the case when:

* Root cause is identified, and
* No successful logon compromise is observed.

## Example Event

| Field  | Value        |
| ------ | ------------ |
| host   | wrk-abungst  |
| user   | al.bungstien |
| src_ip | 127.0.0.1    |
| count  | 745          |

## Expected Outcome

The playbook automatically creates a case, enriches host and user information, classifies the event as a local authentication anomaly, and notifies the SOC analyst for final review.

## Author

Shrikant Raut
