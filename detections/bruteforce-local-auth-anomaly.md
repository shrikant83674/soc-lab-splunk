# Brute Force / Local Authentication Anomaly Detection

## Purpose

Detect repeated failed Windows logons from the same host and user account.

## Detection Query

```spl id="9n4k2m"
index=botsv2 sourcetype=wineventlog EventCode=4625
| stats count by host, user, src_ip
| where count >= 100
| sort - count
```

## Expected Alert

* Host: wrk-abungst
* User: al.bungstien
* Source IP: 127.0.0.1
* Failed logons: 745

## Severity

Medium

## MITRE ATT&CK Mapping

* T1110 - Brute Force

## Author

Shrikant Raut



## Detection Result

The detection query was executed against the `botsv2` dataset and returned the following alerts:

| Host        | User          | Source IP  | Count |
| ----------- | ------------- | ---------- | ----: |
| mercury     | MERCURY$      | 10.0.1.100 | 15070 |
| wrk-abungst | al.bungstien  | 127.0.0.1  |   745 |
| mercury     | Administrator | 10.0.1.220 |   513 |

### Analyst Interpretation

* `wrk-abungst / al.bungstien / 127.0.0.1` matched the investigated local authentication anomaly.
* `mercury / Administrator / 10.0.1.220` represents a separate suspicious authentication pattern and should be triaged as a new alert.
* Machine-account activity (`MERCURY$`) may be related to system authentication behavior and should be validated against expected infrastructure activity.
