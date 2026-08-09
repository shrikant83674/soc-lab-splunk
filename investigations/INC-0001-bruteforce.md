# INC-0001 - Possible Brute Force Authentication Attack

## Incident Summary

This incident was generated from a Splunk correlation search that detected multiple failed Windows authentication events (EventCode 4625). The investigation aims to identify the attacking IP address, targeted user account, and determine whether authentication eventually succeeded.

## Detection Query

```spl
index=botsv2 sourcetype=wineventlog:security EventCode=4625
| stats count by src_ip, user
| sort - count
| head 10
```

## Initial Triage



## Findings

* User account investigated: **al.bungstien**
* Failed logons observed: **745**
* Source IP: **127.0.0.1 (localhost)**
* Affected host: **wrk-abungst**
* Activity distributed over an extended time period.
* Successful logons for the same user and host: **0**.


## Impact Assessment

No evidence of account compromise was identified. The activity appears to be a local authentication anomaly rather than an external brute-force attack. Business impact is considered **Low to Medium**, limited to repeated authentication failures on a single workstation.


## Recommended Actions

1. Review scheduled tasks on `wrk-abungst`.
2. Review Windows services using stored credentials.
3. Check cached credentials and recent password changes for `al.bungstien`.
4. Review application logs on `wrk-abungst` for repeated authentication attempts.
5. Monitor for additional failed logons from other hosts.


## MITRE ATT&CK Mapping

* Technique: T1110 - Brute Force

## Analyst

Shrikant Raut

____________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________


# INC-0001 - Possible Brute Force Authentication Attack

## Incident Summary

This incident was generated from a Splunk correlation search that detected multiple failed Windows authentication events (EventCode 4625). The investigation aims to identify the attacking IP address, targeted user account, and determine whether authentication eventually succeeded.

## Detection Query

```spl id="l2a1u3"
index=botsv2 sourcetype=wineventlog:security EventCode=4625
| stats count by src_ip, user
| sort - count
| head 10
```

## Initial Triage

### Query 1

```spl id="h9f2k1"
index=botsv2 sourcetype=wineventlog:security EventCode=4625
| stats count by src_ip, user
| sort - count
| head 10
```

**Result:** No events returned.

### Analyst Action

Validated available sourcetypes in the `botsv2` index to identify the correct Windows event sourcetype.

### Query 2

```spl id="wpr2i3"
index=botsv2
| stats count by sourcetype
| sort - count
```

### Top Sourcetypes Observed

* WinRegistry: 371,660
* Perfmon:Process: 307,275
* mysql:server:stats: 108,817
* mysql:transaction:details: 107,135
* collectd: 98,148
* ps: 39,910
* mysql:variables: 27,084
* WinHostMon: 22,525
* Perfmon:LogicalDisk: 20,139
* mysql:status: 18,856
* stream:ip: 16,857
* Perfmon:PhysicalDisk: 16,744
* suricata: 15,407
* wineventlog: 14,492
* stream:tcp: 14,124

**Observation:** The `botsv2` index contains Windows event logs under the sourcetype `wineventlog`, confirming that Windows authentication events are available for investigation.

### Initial Assessment

Windows events are present under the sourcetype `wineventlog`. The original query likely failed because the field `EventCode` is not present or uses a different field name in this dataset.

## Findings

Pending.


### Query 3

```spl id="y7n4q2"
index=botsv2 sourcetype=wineventlog
| stats count by EventCode
| sort - count
| head 20
```


---->
**Result:** Windows authentication event IDs were identified successfully.

* 4625 (Failed logon): 1,442 events
* 4624 (Successful logon): 33,627 events

**Assessment:** The dataset contains both failed and successful authentication events, confirming that a brute-force investigation can continue using EventCode 4625 and EventCode 4624.

### Query 4

```spl id="q4"
index=botsv2 sourcetype=wineventlog EventCode=4625
| stats count by user
| sort - count
| head 10
```
-------> 

**Result:**

| User          | Failed Logons |
| ------------- | ------------: |
| MERCURY$      |        15,070 |
| al.bungstien  |           745 |
| Administrator |           519 |
| Guest         |            53 |
| mkraeusen     |             4 |
| administrator |             3 |
| hawkeye       |             2 |

**Assessment:**

* `MERCURY$` is a machine account and is not the primary brute-force target.
* `al.bungstien` shows a high number of failed logons (745) and is considered the most suspicious user account.
* `Administrator` also shows elevated failed logon activity (519) and should be investigated further.

### Query 5

index=botsv2 sourcetype=wineventlog EventCode=4625 user="al.bungstien"
| stats count by src_ip
| sort - count
| head 10

--->

Result:

Source IP	Failed Logons
127.0.0.1	745

Assessment:

All failed logon attempts for al.bungstien originated from 127.0.0.1 (localhost). This suggests the activity is occurring locally on the host rather than from an external network source. The investigation focus shifts toward a local process, service, scheduled task, or application repeatedly attempting authentication.

### Query 6

```spl id="q6"
index=botsv2 sourcetype=wineventlog EventCode=4625 user="al.bungstien"
| stats count by host
| sort - count
```

**Result:**

| Host        | Failed Logons |
| ----------- | ------------: |
| wrk-abungst |           745 |

**Assessment:**

All failed logon events for `al.bungstien` were generated by the host `wrk-abungst`. Combined with the source IP `127.0.0.1`, this indicates the authentication attempts originated locally on the workstation `wrk-abungst`.

### Query 7

```spl id="q7"
index=botsv2 sourcetype=wineventlog EventCode=4625 user="al.bungstien"
| timechart span=5m count
```

**Observation:**

The failed logon events are spread across a long time period rather than occurring in a single short burst. No significant spike was observed in the sampled output.

**Assessment:**

The activity appears consistent with a persistent local authentication issue (service, application, scheduled task, or script repeatedly attempting logon) rather than a rapid brute-force attack.

### Query 8

```spl id="q8"
index=botsv2 sourcetype=wineventlog EventCode=4624 user="al.bungstien" host="wrk-abungst"
| stats count earliest(_time) as first_success latest(_time) as last_success
```

**Result:**

* Successful logons found: **0**

**Assessment:**

No successful authentication events were observed for `al.bungstien` on `wrk-abungst`. The repeated failed logons did not result in a successful compromise.
