# Network Monitoring Tool

A Python-based tool created for a **Junior Developer Trainee** application at **T-Mobile**. It reads device data from an XML file, pings the devices to check connectivity, and outputs the status (online/offline) in XML format or via a web interface.

## Skills Demonstrated
- Python, XML, Unix/Linux commands
- Problem-solving and automation

## Features
- **XML Parsing**: Reads device info from XML.
- **Ping Checks**: Verifies if devices are online or offline.
- **CLI & Web Interface**: Offers both command-line and web-based access (via Flask).
- **Multi-threaded**: Efficiently pings multiple devices in parallel.

## How to Run

### 1. Clone the Repository
```bash
git clone https://github.com/armesha/demo-network-monitoring.git
cd demo-network-monitoring
```

### 2. Install Dependencies
Make sure to install all required dependencies before running the project:
```bash
pip install -r requirements.txt
```

The `requirements.txt` includes:
- Flask==3.0.3

### 3. Run in CLI Mode
```bash
python3 network_monitor.py
```

### 4. Run in Web Interface Mode
```bash
python3 network_monitor.py web
```
Access the web interface at `http://localhost:5000`.

### 5. Run Unit Tests
```bash
python3 network_monitor.py test
```

## Example XML (`devices.xml`)
```xml
<network>
  <device>
    <name>Router_A</name>
    <ip>192.168.1.1</ip>
  </device>
  <device>
    <name>Switch_B</name>
    <ip>192.168.1.2</ip>
  </device>
  <device>
    <name>Public_DNS</name>
    <ip>8.8.8.8</ip>
  </device>
</network>
```