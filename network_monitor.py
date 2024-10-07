#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import subprocess
import platform
import threading
import logging
import time
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template_string, request, redirect, url_for
import unittest
from unittest.mock import patch, Mock

# Configuration
INPUT_XML = 'devices.xml'
OUTPUT_XML = 'network_status.xml'
LOG_FILE = 'network_monitor.log'
PING_TIMEOUT = 2
RETRIES = 3
MAX_THREADS = 10

# Setup Logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Device Data Class
class Device:
    def __init__(self, name, ip):
        self.name = name
        self.ip = ip
        self.status = 'unknown'
        self.latency = None
        self.packet_loss = None

    def to_xml_element(self):
        device_elem = ET.Element('device')
        name_elem = ET.SubElement(device_elem, 'name')
        name_elem.text = self.name
        ip_elem = ET.SubElement(device_elem, 'ip')
        ip_elem.text = self.ip
        status_elem = ET.SubElement(device_elem, 'status')
        status_elem.text = self.status
        latency_elem = ET.SubElement(device_elem, 'latency')
        latency_elem.text = str(self.latency) if self.latency else 'N/A'
        packet_loss_elem = ET.SubElement(device_elem, 'packet_loss')
        packet_loss_elem.text = str(self.packet_loss) if self.packet_loss else 'N/A'
        return device_elem

# XML Handler
class XMLHandler:
    def __init__(self, input_file):
        self.input_file = input_file
        self.devices = []

    def load_devices(self):
        self.devices.clear()  # Clear existing devices to prevent duplication
        try:
            tree = ET.parse(self.input_file)
            root = tree.getroot()
            for device_elem in root.findall('device'):
                name = device_elem.find('name').text
                ip = device_elem.find('ip').text
                device = Device(name, ip)
                self.devices.append(device)
            logging.info(f"Loaded {len(self.devices)} devices from {self.input_file}")
        except Exception as e:
            logging.error(f"Error loading XML: {e}")
            sys.exit(1)

    def save_status(self, output_file):
        network_status = ET.Element('network_status')
        for device in self.devices:
            network_status.append(device.to_xml_element())
        tree = ET.ElementTree(network_status)
        try:
            tree.write(output_file, encoding='utf-8', xml_declaration=True)
            logging.info(f"Saved network status to {output_file}")
        except Exception as e:
            logging.error(f"Error saving XML: {e}")

    def add_device(self, name, ip):
        for device in self.devices:
            if device.name == name or device.ip == ip:
                logging.warning(f"Device with name '{name}' or IP '{ip}' already exists.")
                return False
        new_device = Device(name, ip)
        self.devices.append(new_device)
        self._save_devices()
        logging.info(f"Added device: {name} - {ip}")
        return True

    def remove_device(self, identifier):
        for device in self.devices:
            if device.name == identifier or device.ip == identifier:
                self.devices.remove(device)
                self._save_devices()
                logging.info(f"Removed device: {device.name} - {device.ip}")
                return True
        logging.warning(f"Device '{identifier}' not found.")
        return False

    def _save_devices(self):
        network = ET.Element('network')
        for device in self.devices:
            device_elem = ET.SubElement(network, 'device')
            name_elem = ET.SubElement(device_elem, 'name')
            name_elem.text = device.name
            ip_elem = ET.SubElement(device_elem, 'ip')
            ip_elem.text = device.ip
        tree = ET.ElementTree(network)
        try:
            tree.write(self.input_file, encoding='utf-8', xml_declaration=True)
            logging.info(f"Updated devices saved to {self.input_file}")
        except Exception as e:
            logging.error(f"Error saving devices XML: {e}")

# Network Checker
class NetworkChecker:
    def __init__(self, devices):
        self.devices = devices

    def ping_device(self, device):
        system = platform.system().lower()
        if system == 'windows':
            command = ['ping', '-n', '1', '-w', str(PING_TIMEOUT * 1000), device.ip]
        else:
            command = ['ping', '-c', '1', '-W', str(PING_TIMEOUT), device.ip]
        try:
            start_time = time.time()
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            latency = (time.time() - start_time) * 1000  # in ms
            device.status = 'online'
            device.latency = round(latency, 2)
            device.packet_loss = 0
            logging.info(f"Ping successful: {device.name} - {device.ip} in {device.latency}ms")
        except subprocess.CalledProcessError as e:
            device.status = 'offline'
            device.latency = None
            device.packet_loss = 100
            logging.warning(f"Ping failed: {device.name} - {device.ip}")

    def check_all_devices(self):
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(self.ping_device, device): device for device in self.devices}
            for future in as_completed(futures):
                device = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error checking device {device.name}: {e}")

# CLI Interface
def print_menu():
    print("\nNetwork Monitoring Tool")
    print("1. View Network Status")
    print("2. Add Device")
    print("3. Remove Device")
    print("4. Run Network Check")
    print("5. Exit")

def view_status(xml_handler):
    xml_handler.save_status(OUTPUT_XML)
    print(f"\nNetwork Status saved to {OUTPUT_XML}")
    print("{:<10} {:<15} {:<10} {:<15} {:<15}".format("Name", "IP", "Status", "Latency (ms)", "Packet Loss (%)"))
    for device in xml_handler.devices:
        latency = f"{device.latency}ms" if device.latency is not None else "N/A"
        packet_loss = f"{device.packet_loss}%" if device.packet_loss is not None else "N/A"
        print("{:<10} {:<15} {:<10} {:<15} {:<15}".format(device.name, device.ip, device.status, latency, packet_loss))

def add_device_cli(xml_handler):
    name = input("Enter device name: ")
    ip = input("Enter device IP: ")
    if xml_handler.add_device(name, ip):
        print(f"Device {name} added successfully.")
    else:
        print("Failed to add device. It may already exist.")

def remove_device_cli(xml_handler):
    identifier = input("Enter device name or IP to remove: ")
    if xml_handler.remove_device(identifier):
        print(f"Device '{identifier}' removed successfully.")
    else:
        print("Failed to remove device. It may not exist.")

def run_network_check(xml_handler):
    checker = NetworkChecker(xml_handler.devices)
    checker.check_all_devices()
    xml_handler.save_status(OUTPUT_XML)
    print("Network check completed. Status updated.")

def cli_interface(xml_handler):
    while True:
        print_menu()
        choice = input("Enter your choice: ")
        if choice == '1':
            view_status(xml_handler)
        elif choice == '2':
            add_device_cli(xml_handler)
        elif choice == '3':
            remove_device_cli(xml_handler)
        elif choice == '4':
            run_network_check(xml_handler)
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

# Flask Web Interface
app = Flask(__name__)
xml_handler_flask = XMLHandler(INPUT_XML)
xml_handler_flask.load_devices()

@app.route('/')
def index():
    xml_handler_flask.save_status(OUTPUT_XML)
    devices = xml_handler_flask.devices
    html = '''
    <h1>Network Status</h1>
    <table border="1" cellpadding="5" cellspacing="0">
        <tr>
            <th>Name</th>
            <th>IP</th>
            <th>Status</th>
            <th>Latency (ms)</th>
            <th>Packet Loss (%)</th>
        </tr>
        {% for device in devices %}
        <tr>
            <td>{{ device.name }}</td>
            <td>{{ device.ip }}</td>
            <td>{{ device.status }}</td>
            <td>{{ device.latency if device.latency else 'N/A' }}</td>
            <td>{{ device.packet_loss if device.packet_loss else 'N/A' }}</td>
        </tr>
        {% endfor %}
    </table>
    <br>
    <a href="/run_check">Run Network Check</a><br>
    <a href="/add_device">Add Device</a><br>
    <a href="/remove_device">Remove Device</a>
    '''
    return render_template_string(html, devices=devices)

@app.route('/run_check')
def run_check():
    checker = NetworkChecker(xml_handler_flask.devices)
    checker.check_all_devices()
    xml_handler_flask.save_status(OUTPUT_XML)
    return redirect(url_for('index'))

@app.route('/add_device', methods=['GET', 'POST'])
def add_device():
    if request.method == 'POST':
        name = request.form['name']
        ip = request.form['ip']
        xml_handler_flask.add_device(name, ip)
        return redirect(url_for('index'))
    html = '''
    <h1>Add Device</h1>
    <form method="post">
        Name: <input type="text" name="name" required><br><br>
        IP: <input type="text" name="ip" required><br><br>
        <input type="submit" value="Add">
    </form>
    <br>
    <a href="/">Back to Network Status</a>
    '''
    return render_template_string(html)

@app.route('/remove_device', methods=['GET', 'POST'])
def remove_device():
    if request.method == 'POST':
        identifier = request.form['identifier']
        xml_handler_flask.remove_device(identifier)
        return redirect(url_for('index'))
    html = '''
    <h1>Remove Device</h1>
    <form method="post">
        Name or IP: <input type="text" name="identifier" required><br><br>
        <input type="submit" value="Remove">
    </form>
    <br>
    <a href="/">Back to Network Status</a>
    '''
    return render_template_string(html)

# Unit Tests
class TestXMLHandler(unittest.TestCase):
    def setUp(self):
        self.test_xml = 'test_devices.xml'
        with open(self.test_xml, 'w') as f:
            f.write('''<network>
  <device>
    <name>Dewas_A</name>
    <ip>192.168.1.10</ip>
  </device>
  <device>
    <name>Dewas_B</name>
    <ip>192.168.1.20</ip>
  </device>
  <device>
    <name>Dewas_C</name>
    <ip>192.168.1.30</ip>
  </device>
  <device>
    <name>Dewas_D</name>
    <ip>8.8.8.8</ip>
  </device>
</network>''')
        self.xml_handler = XMLHandler(self.test_xml)
        self.xml_handler.load_devices()

    def tearDown(self):
        if os.path.exists(self.test_xml):
            os.remove(self.test_xml)
        if os.path.exists(OUTPUT_XML):
            os.remove(OUTPUT_XML)

    def test_load_devices(self):
        self.assertEqual(len(self.xml_handler.devices), 4)
        self.assertEqual(self.xml_handler.devices[0].name, 'Dewas_A')
        self.assertEqual(self.xml_handler.devices[3].ip, '8.8.8.8')

    def test_add_device(self):
        result = self.xml_handler.add_device('Dewas_E', '192.168.1.40')
        self.assertTrue(result)
        self.assertEqual(len(self.xml_handler.devices), 5)

    def test_add_existing_device(self):
        result = self.xml_handler.add_device('Dewas_A', '192.168.1.10')
        self.assertFalse(result)
        self.assertEqual(len(self.xml_handler.devices), 4)

    def test_remove_device_by_name(self):
        result = self.xml_handler.remove_device('Dewas_B')
        self.assertTrue(result)
        self.assertEqual(len(self.xml_handler.devices), 3)

    def test_remove_device_by_ip(self):
        result = self.xml_handler.remove_device('8.8.8.8')
        self.assertTrue(result)
        self.assertEqual(len(self.xml_handler.devices), 3)

    def test_remove_nonexistent_device(self):
        result = self.xml_handler.remove_device('Nonexistent')
        self.assertFalse(result)
        self.assertEqual(len(self.xml_handler.devices), 4)

class TestNetworkChecker(unittest.TestCase):
    @patch('subprocess.check_output')
    def test_ping_device_online(self, mock_ping):
        # Simulate successful ping
        mock_ping.return_value = "Reply from 8.8.8.8: bytes=32 time=23ms TTL=117"
        device = Device('Dewas_D', '8.8.8.8')
        checker = NetworkChecker([device])
        checker.ping_device(device)
        self.assertEqual(device.status, 'online')
        self.assertIsNotNone(device.latency)
        self.assertEqual(device.packet_loss, 0)

    @patch('subprocess.check_output')
    def test_ping_device_offline(self, mock_ping):
        # Simulate failed ping
        mock_ping.side_effect = subprocess.CalledProcessError(1, ['ping'])
        device = Device('Dewas_B', '192.0.2.1')
        checker = NetworkChecker([device])
        checker.ping_device(device)
        self.assertEqual(device.status, 'offline')
        self.assertIsNone(device.latency)
        self.assertEqual(device.packet_loss, 100)

    @patch('subprocess.check_output')
    def test_ping_device_local(self, mock_ping):
        # Simulate successful ping to localhost
        mock_ping.return_value = "Reply from 127.0.0.1: bytes=32 time=1ms TTL=128"
        device = Device('Dewas_Local', '127.0.0.1')
        checker = NetworkChecker([device])
        checker.ping_device(device)
        self.assertEqual(device.status, 'online')
        self.assertIsNotNone(device.latency)
        self.assertEqual(device.packet_loss, 0)

    @patch('subprocess.check_output')
    def test_ping_device_invalid(self, mock_ping):
        # Simulate ping with no response
        mock_ping.side_effect = subprocess.CalledProcessError(1, ['ping'])
        device = Device('Dewas_Invalid', '256.256.256.256')  # Invalid IP
        checker = NetworkChecker([device])
        checker.ping_device(device)
        self.assertEqual(device.status, 'offline')
        self.assertIsNone(device.latency)
        self.assertEqual(device.packet_loss, 100)

    @patch('subprocess.check_output')
    def test_check_all_devices(self, mock_ping):
        # Simulate mixed ping results
        def side_effect(command, *args, **kwargs):
            ip = command[-1]
            if ip == '8.8.8.8' or ip == '127.0.0.1':
                return "Reply from {}: bytes=32 time=23ms TTL=117".format(ip)
            else:
                raise subprocess.CalledProcessError(1, command)
        
        mock_ping.side_effect = side_effect
        devices = [
            Device('Dewas_A', '8.8.8.8'),
            Device('Dewas_B', '192.0.2.1'),
            Device('Dewas_C', '127.0.0.1'),
            Device('Dewas_D', '256.256.256.256')
        ]
        checker = NetworkChecker(devices)
        checker.check_all_devices()
        self.assertEqual(devices[0].status, 'online')
        self.assertEqual(devices[1].status, 'offline')
        self.assertEqual(devices[2].status, 'online')
        self.assertEqual(devices[3].status, 'offline')

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        # Remove the 'test' argument to prevent unittest from processing it
        sys.argv.pop(1)
        unittest.main()
    elif len(sys.argv) > 1 and sys.argv[1] == 'web':
        xml_handler_flask.load_devices()
        app.run(host='0.0.0.0', port=5000)
    else:
        xml_handler = XMLHandler(INPUT_XML)
        xml_handler.load_devices()
        cli_interface(xml_handler)
