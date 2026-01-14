 # Detection & Threat Simulation

## Overview
This project demonstrates hands-on SOC detection techniques using Wazuh SIEM.
The lab focuses on detecting brute-force attacks, suspicious PowerShell activity,
and malware alerts, mapped to the MITRE ATT&CK framework.

---

## Environment
- Ubuntu Linux (SSH, Wazuh Manager)
- Windows 11 (Wazuh Agent, Sysmon)
- Kali Linux (Attacking Machine)
- Wazuh SIEM
- MITRE ATT&CK

---

## 🔐 SSH Brute Force Detection (T1110)
- Simulated repeated SSH failed login attempts
- Monitored /var/log/auth.log
- Detected brute-force behavior using Wazuh rules
- MITRE ATT&CK: T1110

## Attack Simulation
- Enabled SSH service on Ubuntu
- Performed repeated failed SSH login attempts from Kali Linux using invalid credentials
- Generated multiple authentication failures in /var/log/auth.log

📸 Screenshots:
![SSH_ENABLE](Screenshots/Enabling_SSH_on_Ubuntu.png)
![Attack](Screenshots/Attacking_Machine.png)
![VAR](Screenshots/var_log.png)

## Detection & Analysis
- Monitored Linux authentication logs via Wazuh agent
- Detected brute-force behavior through Wazuh correlation rules
- Alert mapped to MITRE ATT&CK technique T1110 (Brute Force)

📸 Screenshots:
![wazuh](Screenshots/wazuh_alert_ssh.png)
![mitre](Screenshots/Mitre_Attack.png)

---

## 🖥️ Windows Authentication Failure (T1110)
- Simulated repeated Windows authentication failures
- Analyzed Event ID 4625
- Detected brute-force behavior in Wazuh

📸 Screenshots:
![Auth](Screenshots/logon_4625.png)
![Wazuh](Screenshots/wazuh_4625.png)
![T15](Screenshots/T153.png)

---

## 🧠 PowerShell Abuse Detection (T1059.001)
- Simulated suspicious PowerShell execution
- Detected PowerShell process creation using Sysmon
- Investigated activity in Wazuh SIEM
- MITRE ATT&CK: T1059.001

📸 Screenshot: 
![sysmon](Screenshots/sysmon_log.png)
![pshell](Screenshots/wazuh_pshell.png)

---

## 🦠 Malware Detection – EICAR Test
- Triggered antivirus detection using EICAR test file
- Analyzed Windows Defender alerts
- Verified malware alert ingestion into Wazuh
- MITRE ATT&CK: T1204

📸 Screenshot:
![operation](Screenshots/operation.png)
![orotect](Screenshots/protection.png)
![defender](Screenshots/defender.png)
![malware](Screenshots/malware.png)



---

## Key Skills Demonstrated
- SIEM log analysis
- Threat detection & investigation
- MITRE ATT&CK mapping
- Endpoint security monitoring
- SOC analyst workflows
