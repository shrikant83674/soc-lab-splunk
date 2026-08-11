# Port 135 Scan Detection

## Purpose

Detect repeated Suricata alerts indicating unusual traffic targeting Windows RPC/DCOM port 135 from the same source IP.

## Detection Query

```spl id="d3t3ct"
index=botsv2 sourcetype=suricata
| search alert.signature="ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection"
| stats count by src_ip, dest_ip, dest_port
| where count >= 100
| sort - count
```

## Detection Logic

* Monitor Suricata IDS alerts for the Port 135 scan signature.
* Group events by source IP, destination IP, and destination port.
* Trigger an alert when **100 or more events** are observed for the same communication pair.

## Expected Alert

* Source IP: 10.0.1.1
* Destination IP: 10.0.1.100
* Destination Port: 135
* Alert Count: 5,330

## Severity

Medium

## MITRE ATT&CK Mapping

* T1046 - Network Service Discovery
* T1018 - Remote System Discovery

## Author

Shrikant Raut
