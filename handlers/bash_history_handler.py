import os
from .base_handler import BaseHandler
from typing import Dict, Any, List
import logging
from termcolor import colored
from config import BASH_HISTORY_PATHS
import glob
import fnmatch

class BashHistoryHandler(BaseHandler):
    @classmethod
    def can_handle(cls, logsource: Dict[str, Any]) -> bool:
        if not isinstance(logsource, dict):
            return False
        return logsource.get('category') == 'bash_history'

    @classmethod
    def parse_rule(cls, detection: Dict[str, Any]):
        # Accept 'commands', 'keywords', or 'tools' as the list of suspicious commands
        commands = None
        for key in ['commands', 'keywords', 'tools']:
            if key in detection and detection[key] is not None:
                commands = detection[key]
                break
        if commands is None:
            raise ValueError("No 'commands', 'keywords', or 'tools' field found in detection section of the rule.")
        return {'commands': commands}

    def __init__(self, config):
        self.commands = [cmd.lower() for cmd in config['commands']]

    def _find_bash_history_files(self, vm_path: str) -> List[str]:
        found_files = []
        for rel_path in BASH_HISTORY_PATHS:    
            abs_path = os.path.join(vm_path, rel_path)
            if os.path.exists(abs_path):
                found_files.append(abs_path)
                
        return found_files

    def check(self, vm_path: str, rule, rule_number=None) -> List[str]:
        matches = []
        header = f"{rule_number}. {rule.title}:" if rule_number is not None else f"{rule.title}:"
        logging.info(colored(header, 'magenta'))
        
        history_files = self._find_bash_history_files(vm_path)
        if not history_files:
            logging.warning(colored(f"   No .bash_history files found in any known location for {vm_path}", 'yellow'))
            return matches

        for hist_path in history_files:
            logging.info(colored(f"   Checking {hist_path} for (ID: {rule.id})", 'cyan'))
            with open(hist_path, 'r', errors='ignore') as f:
                for line in f:
                    line_lower = line.strip().lower()
                    # Use fnmatch to check if the line matches any of the command patterns
                    if any(fnmatch.fnmatch(line_lower, cmd) for cmd in self.commands):
                        matches.append(f"{hist_path}: {line.strip()}")
        
        return matches 