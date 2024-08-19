# Elastic Stack Lab: Step-by-Step Installation Guide

<div style="text-align: justify">

This guide provides step-by-step instructions on creating a virtual environment in VirtualBox with both an Ubuntu Server VM and a Windows 10 VM. The document also includes detailed steps for installing Elastic Stack 8 on the Ubuntu Server VM. This setup will enable users to conduct security tests on the Windows 10 VM as outlined in this document.

## Outline

1. [VirtualBox Setup](#virtualbox-setup)
2. [Ubuntu Server Installation](#ubuntu-server-installation)
3. [Windows 10 Installation](#windows-10-installation)
3. [Elastic Stack 8 Installation](#elastic-stack-8-installation)
4. [Security Tests](#security-tests)


----------------------------------------------------------------------------------------------------


## VirtualBox Setup

VirtualBox is a free and open-source virtualization software that allows users to run multiple operating systems on a single machine. It provides a platform for testing, development, and running applications in isolated environments.

To install VirtualBox, follow the instructions on [VirtualBox Webpage](https://www.virtualbox.org/wiki/Downloads) according to your system.

<details>
<summary>
<h3>Lab Virtual Network</h3>
</summary>
<span style="color:gray">

In this lab, We will configure on VirtualBox a virtual network with the following components and respective IP addresses:

- **Virtual Switch** (intnet1) - 172.16.1.0/24
    - **Virtual DHCP Server** - 172.16.1.100
    - **Ubuntu Server VM** (Elastic Host)
        - Adapter 1: NAT - 10.0.2.15
        - Adapter 2: Internal Network (intnet1) - 172.16.1.101
    - **Windows 10 VM** (Victim)
        - Adapter 1: NAT - 10.0.2.15
        - Adapter 2: Internal Network (intnet1) - 172.16.1.102
</span>
</details>

<details>
<summary>
<h3>Create an Internal Virtual Network with DHCP Server on VitualBox</h3>
</summary>
<span style="color:gray">

VirtualBox's internal virtual network allows virtual machines to communicate with each other using an isolated network.

Then, set up a virtual network (intnet1) on VirtualBox with a DHCP Server at address `172.16.1.100` and range `172.16.1.101-254` using the command below on the host:

```bash
$ VBoxManage dhcpserver add --network=intnet1 --server-ip=172.16.1.100 --netmask=255.255.255.0 --lower-ip=172.16.1.101 --upper-ip=172.16.1.254 --enable
$ VBoxManage list dhcpservers
```
</span>
</details>


----------------------------------------------------------------------------------------------------


## Ubuntu Server Installation

First, download the [Ubuntu Server 22.04.1](https://releases.ubuntu.com/22.04.1/ubuntu-22.04.1-live-server-amd64.iso) installer ISO, then follow the steps below:

<details>
<summary>
<h3>Step 1: Create a New Virtual Machine (VM)</h3>
</summary>
<span style="color:gray">

On **VirtualBox Manager** click on **New**:

1. **Name and operating system:**
	1. Fill in the fields and click **Next**.
2. **Memory Size:**
	1. Set 4 GB or more and click **Next**.
3. **Hard disk:**
	1. Select **Create a virtual hard disk now** and click **Create**.
4. **Hard disk file type:**
	1. Select **VDI (VirtualBox Disk Image)** and click **Next**.
5. **Storage on physical hard disk:**
	1. Select **Dynamically allocated** and click **Next**.
6. **File location and size:**
	1. Choose **file location**.
	2. **Disk size**: 30 GB
	3. Click on **Create**.
</span>
</details>

<details>
<summary>
<h3>Step 2: Fine Tune the VM</h3>
</summary>
<span style="color:grey">

On **VirtualBox Manager** select the **Ubuntu Server VM** created and click on **Settings**:

1. On **System > Processor**, set **Processor(s)** to 2 CPUs.
2. On **Storage** > **Storage Devices**, click on  **Controller: IDE > Empty**, then click on the disk at the right side of **Optical Drive** and choose the downloaded **Ubuntu Server image**.
3. On **Network** > **Adapter 1** (enp0s3) set:
	1. **Attached to**: NAT
	2. On **Advanced** click on **Port Forwarding**.
		1. On **Port Forwarding Rules** set the following rules to access **Kibana** and **SSH** from the host machine.
		```
		Name            Protocol  Host IP     Host Port   Guest IP    Guest Port
		Kibana          TCP       127.0.0.1   15601       10.0.2.15   5601
		SSH             TCP       127.0.0.1   10022       10.0.2.15   22
		```
		- Using **Port Forwarding** the connections to **HostIP:HostPort** are redirected to **GuestIP:GuestPort**.
		2. Click **Ok**.
4. On **Network > Adapter 2** (enp0s8) set:
	1. **Attached to**: Internal Network
	2. **Name**: intnet1
5. Click on **OK**.
</span>
</details>

<details>
<summary>
<h3>Step 3: Install Ubuntu Server</h3>
</summary>
<span style="color:grey">

On **VirtualBox Manager** select the **Ubuntu Server VM** and click on **Start**:

1. Hit Enter on **Try or Install Ubuntu Server**.
2. Select the **language**.
3. On **Installer update available**:
	1. Select **Continue without updating**.
4. On **Keyboard configuration**:
	1. Select **Layout** and **Variant** and hit Enter on **Done**.
5. On **Choose type of install**:
	1. Choose **Ubuntu Server** and hit Enter on **Done**.
6. On **Network connections**:
	1. `enp0s3 DHCPv4` should be `eth 10.0.2.15/24`.
	2. `enp0s8 DHCPv4` should be `eth 172.16.1.101/24`.
	3. Hit Enter on **Done**.
7. On **Configure proxy** just hit Enter on **Done**.
8. On **Configure Ubuntu archive mirror** just hit Enter on **Done**.
9. On **Guided storage configuration** just leave default and hit Enter on **Done**.
10. On **Storage configuration** just hit Enter on **Done**.
	1. On the message box **Confirm destructive action** click on **Continue**.
11. On **Profile setup** fill the fields ant press Enter on **Done**.
12. On **Upgrade to Ubuntu Pro** select **Skip for now** and hit Enter on **Continue**.
13. On **SSH Setup** select **Install OpenSSH server** and hit Enter on **Done**.
14. On **Featured Server Snaps** just press Enter on **Done** and the installation will     .
15. On **Install complete!** hit Enter on **Cancel update and reboot**, it will take a while to reboot.
16. On **Please remove the installation medium** just hit Enter and it will reboot.
</span>
</details>

<details>
<summary>
<h3>Step 4: Final Adjustments</h3>
</summary>
<span style="color:grey">

After rebooting **log in** with your credentials.

1. Update the system:
	```
	$ sudo apt update
	$ sudo apt upgrade
	```
2. Install useful network packages:
	```
	$ sudo apt install net-tools network-manager
	```
3. Check the network interfaces and IP addresses:
	```
	$ ifconfig
	```
4. Configure a static IP address for the network interface named `enp0s8`, where the Elastic Host will be deployed. Utilize NetworkManager to efficiently manage the additional adapters connected to other networks:
	1. Edit netplan `.yaml` file:
		```
		$ sudo nano /etc/netplan/*yaml
			network:
				version: 2
				renderer: NetworkManager
				ethernets:
				enp0s8:
					dhcp4: no
					addresses: [172.16.1.101/24]
		```
	2. Restrict permissions to avoid warnings, apply the netplan changes, and restart the NetworkManager if needed:
		```
		$ sudo netplan apply
		$ sudo systemctl restart NetworkManager
		```
5. Firewall configuration with UFW:
	1. Allow Firewall ports 9200 (Elasticsearch), 5601 (Kibana - Web UI), 8220 (Fleet), and 22 (SSH).
		```
		$ sudo ufw allow 9200/tcp
		$ sudo ufw allow 5601/tcp
		$ sudo ufw allow 8220/tcp
		$ sudo ufw allow 22/tcp
		$ sudo ufw enable
		$ sudo ufw status
		```
6. Connect to the Ubuntu Server from the host machine by using SSH with the following command:
	```
	$ ssh -oHostKeyAlgorithms=+rsa-sha2-512 -p 10022 user@127.0.0.1
	```
where `-p 10022` is the port set in port forwarding, `user` is the username, and `127.0.0.1` is the localhost (loopback) address. The `-oHostKeyAlgorithms` flag is necessary if the `rsa-sha2-515` algorithm name is not set in the `HostKeyAlgorithms` parameter of the `.ssh/config` file. This will be useful for copying and pasting.
</span>
</details>


----------------------------------------------------------------------------------------------------


## Windows 10 Installation

First, download the [Windows 10](https://www.microsoft.com/en-gb/software-download/windows10ISO) installer ISO, then follow the steps below:

<details>
<summary>
<h3>Step 1: Create a New Virtual Machine (VM)</h3>
</summary>
<span style="color:grey">

On the **VirtualBox Manager** click on **New** to create a new Virtual Machine:

1. Choose **Name**, **Machine Folder**, **Type**, and **Version**.
2. **Memory size**: 4 GB
3. **Hard disk**:
	1. (check) **Create a virtual hard disk now** and click **Create**.
	2. **Hard disk file type**:
		1. (check) **VDI (VirtualBox Disk Image)** and click **Next**.
	3. **Storage on physical hard disk**
		1. (check) **Dynamically allocated** and click **Next**.
	4. **File location and size**:
		1. Choose **file location**.
		2. **Disk size**: 40 GB
		3. Click on **Create**.
	</span>
</details>

<details>
<summary>
<h3>Step 2: Fine Tune the VM</h3>
</summary>
<span style="color:grey">

On **VirtualBox Manager** select the **Windows 10 VN** created and click on **Settings**:

1. Go to **General > Advanced**:
	1. **Shared Clipboard**: Bidirectional
	2. **Drag'n'Drop**: Bidirectional
2. Go to **System > Processor > Processor(s)**: 2 CPU
3. Go to **Display > Screen > Video Memory**: 128 MB
4. On **Storage** on **Storage Devices** click on  **Controller: IDE > Empty** then click on the disk at the right side of **Optical Drive** and and choose the downloaded **Windows 10 image**.
5. Go to **Network**:
	1. **Adapter 1**:
		1. **Attached to**: NAT
	2. **Adapter 2**:
		1. **Attached to**: Internal Network
		2. **Name**: intnet1
6. Click **OK**.
	</span>
</details>

<details>
<summary>
<h3>Step 3: Install Windows 10</h3>
</summary>
<span style="color:grey">

On **VirtualBox Manager** select the **Windows 10 VM** and click on **Sart**.

1. Set **preferences** and click **Next**.
2. Click **Install now**.
3. Click **I don't have a product key**.
4. Select **Windows 10 Pro** and click **Next**.
5. Check **I accept the licence terms** and click **Next**.
6. Select **Custom Install**.
7. Click **Next** to start the installation.
8. After restart just follow the instructions.
	</span>
</details>

<details>
<summary>
<h3>Step 4: Final Adjustments</h3>
</summary>
<span style="color:grey">

1. After setting up is concluded, install the **VirtualBox Guest Additions**:
	1. click on **Devices > Insert Guest Additions CD Image**.
	2. On Windows Explorer, go to the CD drive and execute **VBoxWindowsAdditions-amd64**.
2. Enabling **PowerShell Script Block Logging**:
PowerShell script block logging captures abnormal PowerShell behavior and produces an audit trail of executed code.
    1. Via **Local Group Policy Editor**:
        1. Go to **Local Group Policy Editor** (**Edit group policy** on search).
        2. Go to **Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell**
        3. Right-click on **Turn on PowerShell Script Block Logging** and click on **Edit**
        4. On the **Turn on PowerShell Script Block Logging** window click on **Enabled** then click on **Apply** then click on **OK**.
    5. (Alternatively) Via **registry**:
        1. To configure script block logging via the registry, use the following code on PowerShell while logged in as an administrator.
            ```
            PS> New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force

            PS> Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force

            PS> Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging" -Value 1 -Force

            ```
3. Installing Sysmon:
    1. Download [Microsoft Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
    2. Download the [Sysmon configuration file](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml) for Endpoint Collection.
    3. Install sysmon:
        ```
        PS> .\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
        ```
	</span>
</details>

<details>
<summary>
<h3>Step 5: Create a Snapshot</h3>
</summary>
<span style="color:grey">

On the VM top menu, go to **Machine** > **Take a Snapshot...**, enter the snapshot name and description, then click **OK**.
	</span>
</details>


----------------------------------------------------------------------------------------------------


## Elastic Stack 8 Installation

Elastic Stack is a collection of open-source tools for centralized logging and data analysis. It includes Elasticsearch for search and analytics, Logstash for data processing, Kibana for data visualization, and Beats for data shipping. Together, they provide real-time insights and monitoring capabilities for organizations of all sizes.


<details>
<summary>
<h3>Elasticsearch Installation</h3>
</summary>
<span style="color:gray">

Elasticsearch is the distributed search and analytics engine at the heart of the Elastic Stack. It is where the indexing, search, and analysis magic happens.

1. Download and install the public signing key to be able to install from the apt repository:
    ```
    $ wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
    ```
2. Save the repository definition to `/etc/apt/sources.list.d/elastic-8.x.list` with the command below:
    ```
    $ echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
    ```
3. Update package lists:
    ```
    $ sudo apt update
    ```
4. Install elasticsearch using apt:
    ```
    $ sudo apt install elasticsearch
    ```
- Save the **Security autoconfiguration information** that is at the end of the output of the installation for use later.
5. Start and enable elasticsearch:
    ```
    $ sudo systemctl daemon-reload
    $ sudo systemctl enable elasticsearch.service
    $ sudo systemctl start elasticsearch.service
    ```
6. Use the command below provided by the **elasticsearch installation output** to **reset the password** of the **elastic** user:
    ```
    $ sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -i -u elastic
    ```
7. Test the elasticsearch server using cURL:
    1. The cURL command below will output an **Empty reply from server**.
        ```
        $ curl localhost:9200
        ```
    2. With the **-k (--insecure) flag** the server will return an **authentication error**.
        ```
        $ curl -k https://localhost:9200?pretty
        ```
    3. With the **-k (--insecure) flag** and the **credentials** the server will return a **healthy response**.
        ```
        $ curl -k -u elastic https://localhost:9200?pretty
        ```
</span>
</details>

<details>
<summary>
<h3>Kibana Installation</h3>
</summary>
<span style="color:gray">

Kibana enables you to give shape to your data and navigate the Elastic Stack. With Kibana, you can:

- Search, observe, and protect your data.
- Analyze your data.
- Manage, monitor, and secure the Elastic Stack.

1. Install Kibana using apt:
    ```
    $ sudo apt install kibana
    ```
2. Generate the **enrollment token for Kibana instances** with the command provided by the **elasticsearch installation output**:
    ```
    $ sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
    ```
3. Run the **Kibana setup** and enter the **enrollment token for Kibana**:
    ```
    $ sudo /usr/share/kibana/bin/kibana-setup
    ```
4. At the bottom of `kibana.yml` set the IP address of your machine in the network where the client machines will connect to it:
    ```
    $ sudo nano /etc/kibana/kibana.yml
        # ============= System: Kibana Server ====================
        server.port: 5601
        ...
        server.host: "0.0.0.0"
        ...
        # This section was automatically generated during setup.
        elasticsearch.hosts: ['https://172.16.1.101:9200']
        ...
        xpack.fleet.outputs: [{..., hosts: ['https://172.16.1.101:9200'],...}]
    ```
5. To generate the key run the command:
    ```
    $ sudo /usr/share/kibana/bin/kibana-encryption-keys generate
    ```
6. Paste at the end of the file `kibana.yml` the `xpack.encryptedSavedObjects.encryptionKey` parameter printed under **Settings** at the end of the previous command output:
    ```
    $ sudo nano /etc/kibana/kibana.yml
        xpack.encryptedSavedObjects.encryptionKey: <key>
        xpack.reporting.encryptionKey: <key>>
        xpack.security.encryptionKey: <key>
    ```
7. Start and enable kibana:
    ```
    $ sudo systemctl start kibana.service
    $ sudo systemctl enable kibana.service
    ```
8. Run the command below and wait for Kibana to fire up on `127.0.0.1:5601`:
    ```
    $ watch -n 1 sudo ss -lntp
    ```
</span>
</details>

<details>
<summary>
<h3>Fleet Server and Elastic-agent Installation</h3>
</summary>
<span style="color:gray">

- **Fleet** provides a web-based UI in Kibana for centrally managing Elastic Agents and their policies.
- **Fleet Server** is the mechanism to connect **Elastic Agents** to **Fleet**.
- All communication between the **Fleet UI** and **Fleet Server** happens through **Elasticsearch**.
- **Elastic Agent** is a single, unified way to add monitoring for logs, metrics, and other types of data to a host. It can also protect hosts from security threats, query data from operating systems, forward data from remote services or hardware, and more. **Elastic Agent** runs **Beats** under the covers.
- The data collected by **Elastic Agent** is stored in indices (**data streams**) that are more granular than you’d get by default with the **Beats shippers** or **APM Server**.
- **Agent policies** specify which integrations you want to run and on which hosts.
- **Elastic integrations** provide an easy way to connect Elastic to external services and systems, and quickly get insights or take action. They can collect new sources of data, and they often ship with out-of-the-box assets like dashboards, visualizations, and pipelines to extract structured fields out of logs and events.

1. On the local host go to **Kibana Web UI** on `127.0.0.1:15601`
2. On the Welcome screen click on **Add integrations**.
    1. Search for **fleet** and click on **Fleet Server**.
        1. Click on **Add Fleet Server**.
            1. On **Create agent policy**:
                1. **New agent policy name**: Fleet Server policy
                2. Click on **Save and continue**.
            2. Click on **Add Elastic Agent to your hosts**.
4. **Add Fleet Server**
    - On **Enroll in Fleet** tab:
    1. **Select a policy for Fleet Server**
        1. Select **Fleet Server policy**.
    2. **Choose a deployment mode for security**
        1. Select **Quick start**.
    3. **Add your Fleet Server host**
        1. **Name**: Fleet Server Host
        2. **URL**: `https://172.16.1.101:8220`
        3. Click on **Add Host**.
    4. **Generate a service token**
        1. Click on **Generate service token** and save the token.
    5. **Install Fleet Server to a centralized host**
        1. Copy the commands under **Linux Tar** tab, on the`./elastic-agent install` command check if `--fleet-server-es=https://172.16.1.101:9200`and add the `--insecure` flag at the end of the command, then run these commands on the Fleet Server Host.
            ```
            $ curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.8.2-linux-x86_64.tar.gz
            $ tar xzvf elastic-agent-8.8.2-linux-x86_64.tar.gz
            $ cd elastic-agent-8.8.2-linux-x86_64
            $ sudo ./elastic-agent install \
                --fleet-server-es=https://172.16.1.101:9200 \
                --fleet-server-service-token=<service_token> \
                --fleet-server-policy=8ae4a090-23a1-11ee-9537-a70d2f2b7364 \
                --fleet-server-es-ca-trusted-fingerprint=<ca_fingerprint> \
                --fleet-server-port=8220 \
                --insecure
            ```
        - **NOTE**: The `fleet-server-es-ca-trusted-fingerprint` flag is the SHA256 checksum of the CA used to self-sign Elasticsearch certificates ([command reference](https://www.elastic.co/guide/en/fleet/8.2/elastic-agent-cmd-options.html)), you can check this running the command below:
            ```
            $ sudo openssl x509 -noout -fingerprint -sha256 -inform pem -in /etc/elasticsearch/certs/http_ca.crt
            ```
    6. If **Missing URL for Fleet Server host** appears click on **Fleet Settings** or click on **Close**.
5. Go to **Fleet > Agents** and click on **Add agent**.
6. **Add agent**
    1. **What type of host are you adding?**
        1. Type **Windows Endpoint policy** and click on **Create policy**.
    2. **Enroll in Fleet?**
        1. Select **Enroll in Fleet (recommended)**.
    3. **Install Elastic Agent on your host**
        1. Copy the commands under the **Windows** tab, on the `.\elastic-agent.exe` command check if `--url=https://172.16.1.101:8220` and add `--insecure` at the end of the command, then run these commands on PowerShell as Administrator on the Windows 10 VM.
            ```
            PS> $ProgressPreference = 'SilentlyContinue'
            PS> Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.8.2-windows-x86_64.zip -OutFile elastic-agent-8.8.2-windows-x86_64.zip
            PS> Expand-Archive .\elastic-agent-8.8.2-windows-x86_64.zip -DestinationPath .
            PS> cd elastic-agent-8.8.2-windows-x86_64
            PS> .\elastic-agent.exe install --url=https://172.16.1.101:8220 --enrollment-token=<token> --insecure
            ```
    4. **Agent enrollment confirmed**
        1. Click on **View enrolled agents**.
- **NOTE**: After restarting the Ubuntu Server and accessing Kibana again, the Fleet Server will appear offline and you will have to restart it using the following command:
    ```
    $ sudo elastic-agent restart
    ```
</span>
</details>

<details>
<summary>
<h3>Add Integrations</h3>
</summary>
<span style="color:gray">

#### System Integration

- It is automatically added with the **Fleet Server integration**.
- On **Windows** collect **Application**, **Security**, and **System** logs from **Windows Logs**.
- On **Linux** collect **auth** logs on **/var/log/auth.log** and **syslog** logs from **/var/log/syslog**.

#### Windows Integration

- Collect **Windows events** from **ForwardedEvents**, **PowerShell**, **PowerShell Operational**, and **Sysmon Operational** channel logs.
- Collect **Windows perfmon and service metrics**.
1. Go to **Integrations**, search for **windows** and click on **Windows**.
    1. On **Windows** click on **Add Windows**.
        1. **Configure integration**
            1. **Integration name**: windows-1
        2. **Where to add this integration?**
            1. On **Existing hosts** tab.
                1. **Agent policy**: Windows Endpoint policy
        3. Click on **Save and continue**.
        4. Click on **Save and deploy changes**.

#### Elastic Defend Integration

1. Go to **Integrations**, search for **security** and click on **Elastic Defend**.
    1. On **Elastic Defend** click on **Add Elastic Defend**.
        1. **Configure integration**
            1. **Integration name**: endpoint_security-1
            2. Select **Complete EDR (Endpoint Detection & Response)**
        2. **Where to add this integration?**
            1. **Existing hosts** tab.
                1. **Agent policy**: Windows Endpoint policy
        3. Click on **Save and continue**.
        4. Click on **Save and deploy changes**.

#### Configure Policies

1. Go to **Fleet > Agent policies** and click on **Windows Endpoint policy**.
    1. Click on **endpoint_security-1** to edit.
        1. on **Policy settings > Protections**:
            1. **Type: Malware**; (Check) Malware protections enable
            2. **Protection level**: Detect
            3. Turn ON **Blocklist enabled**.
        2. on **Policy settings > Settings**:
            1. You can **disable event collection** for **Mac** and **Linux**.
            2. Turn ON **Regiter as antivirus**.
        3. Click on **Save integration**.
        4. Click on **Save and deploy changes**.
    2. Click on **system-2** to edit.
        1. Turn OFF **Collect logs from System instances**.
        2. Keep ON **Collect events from the Windows event log**.
        3. Keep ON **Collect metrics from System instances**.
        4. Click on **Save integration**.
        5. Click on **Save and deploy changes**.

#### Rules

1. Go to **Security > Manage** and click on **Rules**.
2. For the **EICAR Malware Test** enable only the **Endpoint Security** rule. If its **last response** is showing **Warning**, it's because no data in the `logs-endpoint.alerts-*` index has been generated yet.
3. For the **MITRE ATT&CK Test with RTA** enable all the rules and disable the following rules:
    1. **My First Rule** rule.
    2. **Multiple Alerts Involving a User** rule.
    3. **Multiple Alerts in Different ATT&CK Tactics on a Single Host** rule.
    4. You can also disable all the rules with **Failed** or **Warning** in the **Last response** field.
</span>
</details>


----------------------------------------------------------------------------------------------------


## Security Tests

The tests below will be performed:

### EICAR Malware Test

The EICAR Malware test is a harmless file created to test antivirus software. It's used to ensure that antivirus programs can detect and remove malicious code.

<details>
<summary>
<h3>EICAR Test Setup</h3>
</summary>
<span style="color:gray">

1. If not using **Elastic Security antivirus**, disable **Windows Security > Virus & threat protection settings > Real-time protection**.
2. Go to **EICAR Anti Malware Testfile website** to download the test files:
  1. Go to https://www.eicar.org/download-anti-malware-testfile/
  2. Click on **More information** then **Continue to the unsafe site (not recommended**.
  3. Download the `eicar.com`, `eicar.com.txt`, `eicar_com.zip`, and `eicarcom2.zip` test files.
3. Extract the files `eicar_com.zip` and `eicarcom2.zip`.
4. In Kibana **Security > Alerts** the actions performed will be detected as Malware.
    - During the downloading of the `eicar.com` and `eicar.com.txt` files it should generate three signals for each file: for the `.tmp`, `.crdownload`, and `eicar.com`/`eicar.com.txt` files.
    - The `eicar_com.zip` and `eicarcom2.zip` files will generate a signal only during the extraction of the `eicar.com` file.
    - Not always are all the signals captured by Elastic Defend.
</span>
</details>

### MITRE ATT&CK Test with Red Team Automation (RTA)

MITRE ATT&CK Test with Red Team Automation (RTA) is a framework that allows organizations to simulate real-world cyber attacks using automated tools and techniques. It helps organizations identify weaknesses in their security defenses and improve their overall security posture.

<details>
<summary>
<h3>MITRE Test Setup</h3>
</summary>
<span style="color:gray">

1. Install [Python 2](https://www.python.org/downloads/release/python-2718/) on Windows.
    1. Add python.exe to Path.
2. Download the [MITTRE ATT&CK Red Team Automation (RTA) project](https://github.com/endgameinc/RTA/archive/master.zip) and extract `RTA-master` to `C:\`.
4. Run the RTA:
    ```
    PS> python.exe C:\RTA-master\run_all.py
    ```
5. Within a few minutes several signals will appear on the Detections page of Kibana.
</span>
</details>

</div>
