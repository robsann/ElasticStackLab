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

## First Scenario: EICAR Malware Test.

### 1. Use Elastic Security Antivirus
Use Elastic Security Antivirus from the Elastic Defender Integration instead of Microsoft Defender Antivirus or disable Real-time protection from Microsoft Defender Antivirus.
<img src="images/1-elastic_security.png" title="EICAR Description-vm"/>

### 2. Disable SmartScreen for Microsof Edge
<img src="images/2-msdefender_smartscreen.png" title="EICAR Description-vm"/>

### 3. EICAR Malware Description
<img src="images/3-eicar_description.png" title="EICAR Description-vm"/>

### 4. EIRCAR Website
<img src="images/4-eicar_website.png" title="EICAR Description-vm"/>

### 5. EICAR Files
EICAR downloaded and extracted files.
<img src="images/5-eicar_files.png" title="EICAR Description-vm"/>

### 6. Elastiv Kibana Discover
<img src="images/6-elastic_analytics_discover.png" title="EICAR Description-vm"/>

### 7. Elastic Scuity Dashboard Overview
<img src="images/7-elastic_security_dashboard.png" title="EICAR Description-vm"/>

### 8. Elastic Security Alerts
<img src="images/8-elastic_security_alerts.png" title="EICAR Description-vm"/>

## Second Scenario: MITRE ATT&CK Test.
