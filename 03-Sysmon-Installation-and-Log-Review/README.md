# Sysmon Installation and Log Review

## Objective
Enhance Windows log visibility by installing Sysmon and analyzing detailed
process and network activity relevant to SOC investigations.

## Activities Performed
- Installed Sysmon on Windows 11 VM
- Reviewed Sysmon Event IDs 1 and 3
- Compared Sysmon logs with Windows Security Event logs

## Key Observations
Sysmon provided richer telemetry including process command-line arguments,
hashes, and network connection details that are not available in standard
Windows logs.


## Sysmon Installation & Configuration Verification
- Sysmon installed on Windows 11 VM
- Configuration file used: sysmonconfig-export.xml

The screenshot below confirms that Sysmon was successfully installed
and configured on the Windows 11 virtual machine.

![Sysmon Installation](screenshots/Sysmon_installation_confirmation.png)

## Sysmon Log Generation

Sysmon logs are actively being generated and recorded in the
Microsoft-Windows-Sysmon/Operational log.

![Sysmon Operational Log](screenshots/Sysmon_Operational_log.png)

## Sysmon Logs in Wazuh SIEM

The screenshot below shows Sysmon logs successfully ingested
into the Wazuh SIEM for centralized monitoring and analysis.

![Wazuh Sysmon Logs](screenshots/wazuh_sysmon_logs.png)

## Sysmon Event ID 1 – Process Creation

The screenshot below shows a Sysmon Event ID 1 capturing process creation
with full command-line details.

![Sysmon Event ID 1](screenshots/event_id_1_powershell.png)

## Sysmon Event ID 3 – Network Connection

Sysmon recorded a network connection initiated by a process.

![Sysmon Event ID 3](screenshots/event_id_3_showing_network_connection.png)


## Sysmon Event Analysis

### Sysmon Event ID 1 – Process Creation
![Sysmon Event ID 1 – Process Creation](screenshots/sysmon_analyze_event_id.png)
Sysmon Event ID 1 records every process created on the system, 
including full command-line arguments, parent process, and file hashes.

Example observed:
- Process: whoami.exe
- CommandLine: "C:\Windows\System32\whoami.exe"
- Parent Process: powershell.exe
- User: WINDOWS11\Yomi

This level of visibility is not available in standard Windows Event ID 4688.


### Sysmon Event ID 3 – Network Connection
![Sysmon Event ID 3 – Network_Connection](screenshots/sysmon_network_connection.png)
Sysmon Event ID 3 captures network connections initiated by processes,
including source and destination IPs, ports, and protocol details.

Observed event:
- Process: Microsoft.SharePoint.exe
- Source IP: 10.0.2.15
- Destination IP: 104.208.16.88
- Destination Port: 443 (HTTPS)
- Protocol: TCP
- User: WINDOWS11\Yomi

This activity was identified as legitimate outbound traffic associated
with Microsoft OneDrive/SharePoint services. Sysmon Event ID 3 is critical
for detecting suspicious outbound connections, command-and-control (C2)
activity, and unauthorized data exfiltration.

## Sysmon vs Windows Event Logs

## Purpose
Compare default Windows Security logs with Sysmon logs to highlight the differences in granularity.

## Comparison Table

| Feature/Event      | Windows Security Log | Sysmon Log                 | Notes |
|--------------------|----------------------|----------------------------|-------|
| Process Creation   | Event ID 4688        | Event ID 1                 | Sysmon shows parent/child info and command line |
| Network Connection | Limited              | Event ID 3                 | Windows logs don’t track every connection |

## Sample Logs
- [Windows Security Logs CSV](comparisons/windows_logs.csv)  
- [Sysmon Logs CSV](comparisons/sysmon_logs.csv)

## Observations
- Sysmon provides more detailed and persistent logging.
- Useful for SOC monitoring, threat hunting, and forensic analysis.


# Key Takeaways: Sysmon Installation and Windows Log Review

This project demonstrates the end-to-end workflow for a SOC analyst. Configuring advanced endpoint logging, centralizing logs in a SIEM, validating alerts, and documenting findings.

---

## 1. Installing and Configuring Sysmon
*What:* Installed Sysmon on Windows to provide detailed, persistent logging (process creation, network connections, file changes, driver loads, etc.).  
*Why it matters in SOC:*  
- Provides high fidelity logs that default Windows logs cannot capture.  
- Essential for detecting malicious activity and performing forensic investigations.  
- Enables tracking of malware execution, lateral movement, and persistence techniques.

---

## 2. Forwarding Logs to Wazuh
*What:* Configured the Windows agent to forward both Sysmon and Windows Security logs to Wazuh Manager and validated log ingestion.  
*Why it matters in SOC:*  
- Centralized logging is critical for monitoring multiple endpoints efficiently.  
- Enables real-time alerting, event correlation, and investigation in a SIEM.  
- Ensures SOC analysts can detect threats across systems proactively.

---

## 3. Basic Alert Investigation
*What:* Triggered test events (failed logins, process creation, file changes) and verified alerts in Wazuh.  
*Why it matters in SOC:*  
- Confirms the logging and alerting setup is functioning correctly.  
- Provides hands-on experience investigating alerts, understanding severity, and tracking context.  
- Demonstrates early detection of suspicious activity.

---

## 4. Comparing Sysmon vs Windows Event Logs
*What:* Compared Windows Security logs with Sysmon logs using CSV exports and tables.  
*Why it matters in SOC:*  
- Highlights the *enhanced visibility* Sysmon provides.  
- Shows which critical events are missing from default logs.  
- Helps SOC analysts prioritize what events to monitor for effective alerting.

---

## 5. Documentation and Reporting
*What:* Exported logs to CSV, created Markdown files with tables, screenshots, and observations.  
*Why it matters in SOC:*  
- Clear documentation supports incident reporting, audits, and compliance.  
- Makes it easier to review incidents, reproduce findings, and onboard team members.  

---

## 6. Overall SOC Relevance
- *Visibility:* Sysmon + Wazuh gives analysts detailed insight into endpoint activities.  
- *Alerting:* Enables actionable alerts for suspicious behavior.  
- *Investigation:* Detailed logs aid root cause analysis and incident response.  
- *Reporting:* Structured documentation allows clear communication of findings.  
- *Skill Development:* Hands-on experience with logging, SIEM integration, and alert investigation is foundational for SOC operations.

---

*Summary Statement:*  
> This project illustrates the full SOC workflow: from endpoint logging (Sysmon) to centralized SIEM monitoring (Wazuh), alert validation, and documentation. Mastery of these steps equips a SOC analyst to detect, investigate, and respond to cyber threats effectively.
