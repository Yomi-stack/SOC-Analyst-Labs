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

# Sysmon Installation and Log Review

## Sysmon Installation Verification

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


