# Windows Event Logging and Telementary Integration

This lab demonstrates *Windows event monitoring* and integration with *Wazuh SIEM*. It includes screenshots of Event Viewer logs, event details, and Wazuh dashboard visibility for key Windows security events.

---

## Lab Overview

The purpose of this lab is to simulate common Windows security events and show how SOC analysts monitor them using both *native Windows tools* and *Wazuh SIEM*.

*Events Covered:*
1. *Event ID 4624* – Successful Logon
2. *Event ID 4625* – Failed Logon
3. *Event ID 4688* – Process Creation

Screenshots show logs in both *Windows Event Viewer* and *Wazuh Dashboard*.

---

## Event ID 4624 – Successful Logon

This event is generated when a user successfully authenticates to a Windows system. SOC analysts use this event to track legitimate access, identify unusual login times, and detect suspicious logon sources.


*Key Fields Reviewed:*
- *TimeCreated* – Timestamp of logon
- *User* – User account that logged in
- *Source* – Machine or service generating the event
- *Logon Type* – Interactive, Remote, etc.

*Screenshots:*

![4624 in Event Viewer](./Ev_4624_success.png)  
![4624 in Wazuh](./Wazuh_4624_success.png)

SOC relevance:
Used to detect unauthorized access and lateral movement.

---

## Event ID 4625 – Failed Logon

This event is generated when a login attempt fails. Repeated occurrences may indicate brute-force attacks or credential misuse

*Key Fields Reviewed:*
- *TimeCreated* – Timestamp of failed logon
- *User* – Account that failed to log in
- *Failure Reason* – Why the logon failed
- *Source* – Machine or service generating the event

*Screenshots:*

![4625 in Event Viewer](./Ev_4625_failure.png)  
![4625 in Wazuh](./Wazuh_4625_failure.png)

SOC relevance:
Critical for detecting brute-force attacks and account enumeration.

---

## Event ID 4688 – Process Creation

This event is generated when a new process is created. SOC analysts monitor this event to detect suspicious or unauthorized process execution.

*Key Fields Reviewed:*
- *New Process Name* – The executable that was launched
- *Parent Process* – Process that spawned this process
- *Command Line* – Full command used (if enabled)
- *User Context* – User that executed the process

*Screenshots:*

![4688 in Event Viewer](./Ev_4688_process.png)  
![4688 in Wazuh](./Wazuh_4688_process.png)

SOC relevance:
Used to detect malware execution, scripting abuse, and privilege escalation.

---

## Lab Notes / Observations

- Event Viewer logs provide detailed information about user activity and system events.  
- Wazuh SIEM collects these logs centrally, allowing correlation and alerting for security events.  
- SOC analysts use this information to *detect suspicious activity*, such as multiple failed logons, unusual process creation, or unauthorized access attempts.  

---

## Screenshots
This lab includes screenshots showing:
- Windows Event Viewer logs for each Event ID
- Event details highlighting key fields
- Log visibility in Wazuh SIEM

## Outcome
Improved understanding of Windows authentication and process execution logs used in SOC investigations.

## Next Steps
- Enhance endpoint telemetry by installing and configuring *Sysmon*.
- Review Sysmon configuration and compare *Sysmon logs with native Windows Security logs*.
- Forward Windows and Sysmon logs to *Wazuh SIEM* and validate successful log ingestion.
- Generate controlled failed authentication attempts to trigger alerts.
- Investigate alerts in Wazuh and document findings in a basic incident report.
