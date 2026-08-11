# INC-0002 - Suspicious Port 135 Scanning Activity

## Incident Summary

This incident was generated from Suricata IDS alerts indicating unusual traffic involving port 135. The investigation aims to identify the source systems, destination systems, and determine whether the activity resembles network scanning or malicious propagation behavior.

## Detection Query

```spl id="8v4p1m"
index=botsv2 sourcetype=suricata
| search alert.signature="ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection"
```

## Initial Triage

### Query 1 - Alert Summary

```spl id="q1-port135"
index=botsv2 sourcetype=suricata
| search alert.signature="ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection"
| stats count by alert.signature
```

## Result

* Alert signature: `ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection`
* Total alerts observed: **5,330**

## Assessment

Suricata generated **5,330 alerts** related to unusual port 135 traffic. The high alert volume indicates sustained or repeated network activity involving Windows RPC/DCOM services and warrants further investigation to identify the source systems and potential scanning behavior.

---

### Query 2 - Source IP Analysis

```spl id="q2-port135"
index=botsv2 sourcetype=suricata
| search alert.signature="ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection"
| stats count by src_ip
| sort - count
| head 10
```

## Result

| Source IP | Alert Count |
| --------- | ----------- |
| 10.0.1.1  |       5,330 |

## Assessment

All observed Port 135 alerts originated from the source IP **10.0.1.1**. The concentration of all alerts on a single source system strongly suggests that this host is the primary originator of the suspicious network activity and should be treated as the main investigation target.

---

### Query 3 - Destination IP Analysis

```spl id="q3-port135"
index=botsv2 sourcetype=suricata
| search alert.signature="ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection"
| stats count by dest_ip
| sort - count
| head 10
```

## Result

| Destination IP | Alert Count |
| -------------- | ----------: |
| 10.0.1.100     |       5,330 |

## Assessment

All Port 135 alerts were directed to the destination IP **10.0.1.100**. The activity is concentrated between a single source and a single destination, indicating repeated communication from **10.0.1.1** to **10.0.1.100** rather than broad network-wide scanning. The destination host should be reviewed for exposed RPC/DCOM services and abnormal authentication or service activity.

---

### Query 4 - Destination Port Analysis

```spl id="q4-port135"
index=botsv2 sourcetype=suricata
| search alert.signature="ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection"
| stats count by dest_port
| sort - count
| head 10
```

## Result

| Destination Port | Alert Count |
| ---------------- | ----------: |
| 135              |       5,330 |

## Assessment

All alerts targeted **destination port 135**, which is commonly associated with Microsoft RPC/DCOM services. High-volume traffic to this port is frequently observed during Windows network reconnaissance, worm propagation, and unauthorized service enumeration activity.

---

### Query 5 - Time Pattern Analysis

```spl id="q5-port135"
index=botsv2 sourcetype=suricata
| search alert.signature="ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection"
| timechart span=30m count
```

## Observation

The alert activity was observed repeatedly across many 30-minute time intervals. Sample values included:

* 2017-08-01 05:30:00 → 1
* 2017-08-01 06:00:00 → 2
* 2017-08-01 08:30:00 → 3
* 2017-08-01 12:30:00 → 4
* 2017-08-01 14:30:00 → 5

## Assessment

The activity occurred continuously over an extended period rather than as a single short burst. This pattern is more consistent with a persistent automated process, service, malware activity, or repeated scheduled communication than with a one-time network scan.

---

## Findings

* Alert signature investigated: **ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection**
* Total alerts observed: **5,330**
* Source IP: **10.0.1.1**
* Destination IP: **10.0.1.100**
* Destination port: **135**
* Activity pattern: **Continuous repeated activity over an extended period**
* Broad network scanning observed: **No**
* Single source to single destination communication: **Yes**

## Impact Assessment

The activity represents sustained communication from **10.0.1.1** to **10.0.1.100** targeting Windows RPC/DCOM services on port 135. No evidence of broad network-wide scanning was identified in this dataset. The behavior is suspicious and may indicate unauthorized service enumeration, persistent automated communication, malware activity, or a misconfigured process.

**Impact level:** Medium

## Recommended Actions

1. Investigate host **10.0.1.1** for scanning tools, malware, scheduled tasks, and unusual network activity.
2. Review host **10.0.1.100** for exposed RPC/DCOM services and related Windows event logs.
3. Check firewall logs for additional connections between the two systems.
4. Validate whether communication between these hosts is expected within the environment.
5. Continue monitoring for new port 135 alerts involving other source systems.

## MITRE ATT&CK Mapping

* **T1046 - Network Service Discovery**
* **T1018 - Remote System Discovery**

## Evidence Screenshots

* Query 1 - Alert summary: `../screenshots/inc-0002-query1-alert-summary.png`
* Query 2 - Source IP analysis: `../screenshots/inc-0002-query2-source-ip.png`
* Query 3 - Destination IP analysis: `../screenshots/inc-0002-query3-destination-ip.png`
* Query 4 - Destination port analysis: `../screenshots/inc-0002-query4-destination-port.png`
* Query 5 - Time pattern analysis: `../screenshots/inc-0002-query5-timechart.png`

## Analyst

Shrikant Raut


