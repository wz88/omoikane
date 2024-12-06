# Kraken - Cisco Configuration Parser

A Python library for parsing and managing network device configurations using Pydantic models and Ansible-like parsing capabilities.

## Features

- Parse device configurations into structured Python objects
- Type-safe configuration handling with Pydantic models
- Support for interfaces, VLANs, routing protocols, and more
- Easy access to parsed configuration data

## Installation

Openssl is needed to run the code. Run the following commands:

```bash
# Install Openssl on mac
brew install openssl

# Install Openssl on ubuntu/debian
sudo apt-get install libssl-dev

# Install Openssl on red hat/centos
sudo yum install openssl-devel
```

Then, set the necessary environment variables to point to your OpenSSL installation:

```bash
export LDFLAGS="-L$(brew --prefix openssl)/lib"
export CPPFLAGS="-I$(brew --prefix openssl)/include"
```

Install the package using pip

```bash
uv add ciscoconfparse2
```

```bash
uv sync
```

## Usage

```python
from src.models import CiscoRouter

# Create a router instance with config
config = """
hostname ROUTER-01
interface GigabitEthernet0/0
 description WAN Interface
 ip address 192.168.1.1 255.255.255.0
 no shutdown
"""

router = CiscoRouter(config)

# Access parsed configuration
print(router.config.hostname)  # ROUTER-01
print(router.get_interface('GigabitEthernet0/0').description)  # WAN Interface
```

## Development

To run tests:
```bash
uv run --dev pytest tests/ -v
```