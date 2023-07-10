# Threat Hunting with Elastic Stack 8
- Configured in VirtualBox:
  - DHCP Server:
    - Ubuntu VM (Elastic Host)
    - Windows 10 VM (Victim)
- Configured Elastic 8.8:
  - Elastic Stack: Elasticsearch and Kibana (Web UI).
  - Integrations: Fleet Server, Elastic Agent, Elastic Defend, System, and Windows.
- Simulated two scenarios:
  - First Scenario: EICAR Malware Test.
  - Second Scenario: MITRE ATT&CK Test.

# Highlights

## 1 - Elastic Host and Victim Setup

### 1.1 - Fleet Agents
<img src="images/1/1-fleet_agents.png" title="Fleet Agents"/>

### 1.2 - Fleet Server Policy
<img src="images/1/2-fleet_server_policy.png" title="Fleet Server Policy"/>

#### 1.2.1 - Fleet Server Integration
<img src="images/1/2.1-fleet_server_integration.png" title="Fleet Server Integration"/>

### 1.3 - Windows Endpoint Policy
<img src="images/1/3-windows_endpoint_policy.png" title="Windows Endpoint Policy"/>

#### 1.3.1 - Elastic Defend Integration
<img src="images/1/3.1-elastic_defend_integration.png" title="Elastic Defend Integration"/>

#### 1.3.2 - System Integration
<img src="images/1/3.2-system_integration.png" title="System Integration"/>

#### 1.3.3 - Winows Integration
<img src="images/1/3.3-windows_integration.png" title="Windows Integration"/>

### 1.4 - Endpoint Security Rule
The Endpoint Security Rule generates a detection alert (signal) each time an Elastic Endpoint Security alert is received. Enabling this rule allows you to investigate your Endpoint alerts on Elastic Security.
<img src="images/1/4-endpoint_security_rule.png" title="Endpoint Security Rule"/>

### 1.5 - Windows Security

#### 1.5.1 - Elastic Security Antivirus
Use Elastic Security Antivirus from the Elastic Defender Integration instead of Microsoft Defender Antivirus or disable Real-time protection from Microsoft Defender Antivirus.
<img src="images/1/5.1-elastic_security_antivirus.png" title="Elastic Security Antivirus"/>

#### 1.5.2 - Microsoft Defender SmartScreen
<img src="images/1/5.2-msdefender_smartscreen.png" title="Microsoft Defender SmartScreen"/>

## 2 - First Scenario: EICAR Malware Test.

### 2.1.1 - EICAR Malware Description
<img src="images/2/1.1-eicar_description.png" title="EICAR Description"/>

### 2.1.2 - EIRCAR Website
<img src="images/2/1.2-eicar_website.png" title="EICAR Website"/>

### 2.1.3 - EICAR Files
EICAR downloaded and extracted files.
<img src="images/2/1.3-eicar_files.png" title="EICAR Downloaded Files"/>

### 2.2.1 - Elastiv Analytics Discover
<img src="images/2/2.1-elastic_analytics_discover.png" title="Analytics Discover"/>

### 2.2.2 - Elastic Scuity Dashboard Overview
<img src="images/2/2.2-elastic_security_dashboard.png" title="Security Dashboard Overview"/>

### 2.2.3 - Elastic Security Alerts
<img src="images/2/2.3-elastic_security_alerts.png" title="Security Alerts"/>

## 3 - Second Scenario: MITRE ATT&CK Test.

### 3.1 - Alerts Over Time
All the 249 alerts detected by 47 distinct rules.
<img src="images/3/1-alerts_over_time.png" title="Alerts Over Time"/>

### 3.2.1 - Detection Rules and Executables
Count of all the Security SIEM detection rules used to create the alerts.
<img src="images/3/2.1-rules_and_executables.png" title="Rules and Executables"/>

### 3.2.2 - Processes per Rule for the Top 10 Rules by Count of Records
<img src="images/3/2.2-processes_per_rule_top10.png" title="Processes per Rule (Top 10)"/>

### 3.3.1 - Detection Rules Techniques and Tactics
<img src="images/3/3.1-rules_tech_tact.png" title="Rules Techiniques Tactics"/>

### 3.3.2 - Command Line of Process and Parent Process per Rule
<img src="images/3/3.2-processes_per_rule.png" title="Processes per Rule"/>


