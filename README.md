 SIEM-Based Brute-Force Detection & Investigation

I used Splunk Enterprise and a simulated authentication-log CSV to practise a basic SOC workflow: importing data, counting failed logins, grouping failures into time windows, comparing outcomes, and reviewing the event timeline.

> **Data note:** This is synthetic training data. The results show a suspicious pattern, not a confirmed attack or account compromise.

Tools and data
- Splunk Enterprise
- Splunk Processing Language (SPL)
- `sample_authentication_logs.csv`
- Index: `main`

Workflow

1. Confirm the data is searchable
```spl
index=main
```
Splunk returned 20 events.

 2. Count failed logins
```spl
index=main action=failure
| stats count by source_ip username
| sort - count
```
The search showed 15 failed events. The largest group was `10.0.0.22` targeting `bob`, with eight failures.

 3. Group failures into five-minute intervals
```spl
index=main action=failure
| eval event_time=strptime(timestamp,"%Y-%m-%d %H:%M:%S")
| bin event_time span=5m
| stats count by event_time source_ip username
| where count >= 5
| sort - count
```
The result showed five failures for `10.0.0.22` / `bob` in the bucket starting at 09:00. Five is a practice threshold, not a universal rule.

 4. Compare failures and successes
```spl
index=main (action=failure OR action=success)
| stats count(eval(action="failure")) as failed_logins
        count(eval(action="success")) as successful_logins
        by source_ip username
| where failed_logins >= 5 AND successful_logins >= 1
| sort - failed_logins
```
This found eight failures and one success for `10.0.0.22` / `bob`. Since this is an aggregate, I checked the individual event timestamps next.

 5. Review the timeline
```spl
index=main source_ip="10.0.0.22" username="bob"
| sort 0 timestamp
| table timestamp source_ip username action event_id
```
The timeline showed five failures from 09:00:18 to 09:01:30, a success at 09:01:48, and three more failures from 09:08:00 to 09:08:40 on 12 October 2026.

Initial finding
Five failures for `bob` from `10.0.0.22` were followed by a successful login 18 seconds after the fifth failure. This deserves further investigation, but does not prove brute-force activity or account compromise.

**Recommended follow-up:** Validate the source IP, inspect the successful logon's logon type, review associated account activity, and correlate with other endpoint or network logs.

Limitations
The CSV contains simulated, simplified events rather than native Windows event records. The screenshots document ingestion, SPL searches, and timeline review; an automated alert and dashboard are not claimed as completed.
