Web Server Characterization using Wireshark Traces
===================================================

This Python script analyzes network traffic captured in a PCAP file using the Scapy library.
It characterizes the behavior of a web server by identifying and analyzing HTTP requests and responses,
computing statistics such as packet counts, arrival times, and divergence between distributions.

Author: Kanran Peng

Purpose
-------

- Count total packets, TCP packets, and UDP packets.
- Identify and timestamp HTTP requests to/from a given server IP and port.
- Analyze time-based behavior of traffic (e.g., inter-arrival times).
- Compute divergence (e.g., Kullback-Leibler divergence) between distributions of observed data.

Requirements
------------

- Python 3.x
- Scapy (`pip install scapy`)

Usage
-----

Run the script with:

    python3 measure-webserver.py <pcap_file> <server_ip> <server_port>

Example:

    python3 measure-webserver.py trace.pcap 192.168.1.10 80

Arguments:
- `<pcap_file>`: Path to the `.pcap` file containing the captured traffic
- `<server_ip>`: IP address of the web server to analyze
- `<server_port>`: Port number of the server (typically 80 for HTTP)

Functions
---------

- `dl(p, q)`: Computes divergence between two distributions using the Kullback-Leibler formula.
- `class node`: Custom class to represent and store metadata for network packets (source, destination, port, etc.)

Notes
-----

- This script is meant for educational or research purposes in analyzing web traffic behavior.
- Ensure the `.pcap` file contains relevant traffic to/from the specified server IP and port.

To Do
-----

- Add support for HTTPS (port 443)
- Improve visualization of timing and request patterns
- Export metrics to CSV for further analysis