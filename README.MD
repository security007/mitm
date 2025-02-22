# MITM TOOL

Python-based MITM (Man-In-The-Middle) tool designed to intercept HTTP and HTTPS requests across the same subnet. This tool uses mitmproxy in transparent mode to capture and log traffic from devices in the same local network range.

## Installation

```bash
pip install mitmproxy
sudo apt install dsniff
```

## Usage

```bash
usage: mitm.py [-h] --target TARGET [--gateway GATEWAY] [--interface INTERFACE] [--port PORT]

MITM Tool

options:
  -h, --help            show this help message and exit
  --target TARGET       Target IP or hostname for the MITM attack
  --gateway GATEWAY     Specify the gateway IP address
  --interface INTERFACE
                        Network interface to use
  --port PORT           Port for mitm proxy

```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.
