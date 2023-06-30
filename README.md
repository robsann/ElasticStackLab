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

## Elastic Host and Victim Setup

### 1 - Fleet Agents
<img src="images/1-fleet_agents.png" title="Fleet Agents"/>

#### 1.1 - Fleet Server Policy
<img src="images/1.1-fleet_server_policy.png" title="Fleet Server Policy"/>

#### 1.1.1 - Fleet Server Integration
<img src="images/1.1.1-fleet_server_integration.png" title="Fleet Server Integration"/>

#### 1.2 - Windows Endpoint Policy
<img src="images/1.2-windows_endpoint_policy.png" title="Windows Endpoint Policy"/>

#### 1.2.1 - Elastic Defend Integration
<img src="images/1.2.1-elastic_defend_integration.png" title="Elastic Defend Integration"/>

#### 1.2.2 - System Integration
<img src="images/1.2.2-system_integration.png" title="System Integration"/>

#### 1.2.3 - Winows Integration
<img src="images/1.2.3-windows_integration.png" title="Windows Integration"/>

### 2 - Endpoint Security Rule
<img src="images/2-endpoint_security_rule.png" title="Endpoint Security Rule"/>

### 3 - Windows Security

#### 3.1 - Elastic Security Antivirus
Use Elastic Security Antivirus from the Elastic Defender Integration instead of Microsoft Defender Antivirus or disable Real-time protection from Microsoft Defender Antivirus.
<img src="images/3.1-elastic_security_antivirus.png" title="Elastic Security Antivirus"/>

#### 3.2 - Microsoft Defender SmartScreen
<img src="images/3.2-msdefender_smartscreen.png" title="Microsoft Defender SmartScreen"/>

## First Scenario: EICAR Malware Test.

### 4.1 - EICAR Malware Description
<img src="images/4.1-eicar_description.png" title="EICAR Description"/>

### 4.2 - EIRCAR Website
<img src="images/4.2-eicar_website.png" title="EICAR Website"/>

### 4.3 - EICAR Files
EICAR downloaded and extracted files.
<img src="images/4.3-eicar_files.png" title="EICAR Downloaded Files"/>

### 5.1 - Elastiv Analytics Discover
<img src="images/5.1-elastic_analytics_discover.png" title="Analytics Discover"/>

### 5.2 - Elastic Scuity Dashboard Overview
<img src="images/5.2-elastic_security_dashboard.png" title="Security Dashboard Overview"/>

### 5.3 - Elastic Security Alerts
<img src="images/5.3-elastic_security_alerts.png" title="Security Alerts"/>

## Second Scenario: MITRE ATT&CK Test.
