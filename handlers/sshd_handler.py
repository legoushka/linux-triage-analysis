from .base_handler import BaseHandler
from typing import Dict, Any, List
import logging
from termcolor import colored

class SSHDLogHandler(BaseHandler):
    @classmethod
    def can_handle(cls, logsource: Dict[str, Any]) -> bool:
        return logsource.get('service') == 'sshd' and logsource.get('product') == 'linux'

    @classmethod
    def parse_rule(cls, detection: Dict[str, Any]):
        return {'keywords': [kw.lower() for kw in detection['keywords']]}

    def __init__(self, config):
        self.keywords = config['keywords']

    def check(self, vm_path: str, rule, rule_number=None) -> List[str]:
        log_file = self._find_auth_log(vm_path)
        header = f"{rule_number}. {rule.title}:" if rule_number is not None else f"{rule.title}:"
        print(colored(header, 'magenta'))
        logging.info(colored(f"   Checking {log_file if log_file else '[not found]'} for (ID: {rule.id})", 'cyan'))
        if not log_file:
            logging.warning(colored(f"   Auth log not found in {vm_path}", 'yellow'))
            return []

        matches = []
        with open(log_file, 'r') as f:
            for line in f:
                line_lower = line.lower()
                if any(keyword in line_lower for keyword in self.keywords):
                    matches.append(line.strip())
        return matches