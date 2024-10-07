# Network Monitoring Tool

A Python-based tool that reads device data from an XML file, pings the devices to check connectivity, and outputs the status (online/offline) in XML format or via a web interface.

## Features
- **XML Parsing**: Reads device info from XML.
- **Ping Checks**: Verifies if devices are online or offline.
- **CLI & Web Interface**: Offers both command-line and web-based access (via Flask).
- **Multi-threaded**: Efficiently pings multiple devices in parallel.

## Skills Demonstrated
- Python, XML, Unix/Linux commands
- Problem-solving and automation

## How to Run

### 1. Clone the Repository
```bash
git clone https://github.com/armesha/demo-network-monitoring.git
cd demo-network-monitoring
```

### 2. Run in CLI Mode
```bash
python3 network_monitor.py
```

### 3. Run in Web Interface Mode
```bash
python3 network_monitor.py web
```
Access at `http://localhost:5000`.

### 4. Run Unit Tests
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