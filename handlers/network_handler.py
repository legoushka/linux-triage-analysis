import re
import os
from typing import Dict, Any, List
from ipaddress import ip_address, ip_network
from .base_handler import BaseHandler
import logging
from termcolor import colored
from config import SS_OUTPUT_FILES

class NetworkConnectionHandler(BaseHandler):
    @classmethod
    def can_handle(cls, logsource: Dict[str, Any]) -> bool:
        return logsource.get('category') == 'network_connection' and logsource.get('product') == 'linux'

    @classmethod
    def parse_rule(cls, detection: Dict[str, Any]):
        config = {
            'ports': [int(port) for port in detection['selection']['DestinationPort']],
            'networks': []
        }
        
        # Handle CIDR filter if present
        # Accept both DestinationIp|cidr and DestinationIp for compatibility
        filter_key = None
        if 'filter_main_local_ranges' in detection:
            if 'DestinationIp|cidr' in detection['filter_main_local_ranges']:
                filter_key = 'DestinationIp|cidr'
            elif 'DestinationIp' in detection['filter_main_local_ranges']:
                filter_key = 'DestinationIp'
            if filter_key:
                cidr_list = detection['filter_main_local_ranges'][filter_key]
                config['networks'] = [ip_network(cidr, strict=False) for cidr in cidr_list]
        
        return config

    def __init__(self, config):
        self.ports = config['ports']
        self.networks = config['networks']

    @staticmethod
    def parse_address_port(address_str):
        match = re.match(r'^\[?([0-9a-fA-F:.]+)\]?:(\d+)$', address_str)
        if match:
            return match.group(1), int(match.group(2))
        raise ValueError(f"Invalid address: {address_str}")

    def check(self, vm_path: str, rule, rule_number=None) -> List[str]:
        network_dir = os.path.join(vm_path, "live_response/network")
        ss_path = None
        for fname in SS_OUTPUT_FILES:
            candidate = os.path.join(network_dir, fname)
            if os.path.exists(candidate):
                ss_path = candidate
                break
        header = f"{rule_number}. {rule.title}:" if rule_number is not None else f"{rule.title}:"
        print(colored(header, 'magenta'))
        logging.info(colored(f"   Checking {ss_path if ss_path else '[not found]'} for (ID: {rule.id})", 'cyan'))
        if not ss_path:
            logging.warning(colored(f"   No suitable ss output file found in {network_dir}", 'yellow'))
            return []

        suspicious = []
        with open(ss_path, 'r') as f:
            for line in f.readlines()[1:]:
                parts = list(filter(None, line.strip().split()))
                if len(parts) < 5:
                    continue

                try:
                    ip, port = self.parse_address_port(parts[4])
                except (ValueError, IndexError):
                    continue

                if port not in self.ports:
                    continue

                try:
                    ip_obj = ip_address(ip)
                    # Skip if IP is in any of the filtered networks
                    if any(ip_obj in network for network in self.networks):
                        continue
                except ValueError:
                    continue

                suspicious.append(f"{ip}:{port}")

        return suspicious