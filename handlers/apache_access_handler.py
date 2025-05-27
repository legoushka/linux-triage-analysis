import os
import re
import logging
from termcolor import colored
from config import APACHE_ACCESS_LOG_PATHS
from sigma.schema import Rule
from typing import List
import fnmatch

class ApacheAccessHandler:
    def __init__(self, config):
        self.config = config

    @staticmethod
    def can_handle(logsource: dict) -> bool:
        return logsource.get('product') == 'apache' and logsource.get('category') == 'accesslog'

    @staticmethod
    def parse_rule(detection: dict):
        # Extract relevant patterns from the Sigma rule and convert URIs to lowercase
        uris = [uri.lower() for uri in detection.get('selection_uris', {}).get('url.path', [])]
        method = detection.get('filter_method', {}).get('http.method', None)
        status = detection.get('filter_status_success', {}).get('http.response.status_code', None)
        return {
            'uris': uris,
            'method': method,
            'status': status
        }
    
    def _find_access_log(self, vm_path: str) -> str:
        for log_path in APACHE_ACCESS_LOG_PATHS:
            full_path = os.path.join(vm_path, log_path)
            if os.path.exists(full_path):
                return full_path
        return None

    def check(self, vm_path: str, rule: Rule, rule_number: int) -> List[str]:
        findings = []
        header = f"{rule_number}. {rule.title}:" if rule_number is not None else f"{rule.title}:"
        logging.info(colored(header, 'magenta'))
        access_log = self._find_access_log(vm_path)
        if not access_log:
            logging.warning(colored(f"   Apache access log not found in any known location for {os.path.basename(vm_path)}", 'yellow'))
            return findings
        logging.info(colored(f"   Checking {access_log} for (ID: {rule.id})", 'cyan'))
        with open(access_log, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                match = re.search(r'"(\w+) ([^ ]+) [^\"]+" (\d+)', line)
                if not match:
                    continue
                method, path, status = match.group(1), match.group(2), match.group(3)
                
                # Convert extracted path to lowercase for case-insensitive matching
                extracted_path_lower = path.lower()

                if self.config['method'] and method != self.config['method']:
                    continue
                if self.config['status'] and str(status) != str(self.config['status']):
                    continue
                for pattern in self.config['uris']:
                    if fnmatch.fnmatch(extracted_path_lower, pattern):
                        findings.append(line.strip())
                        break
        return findings 