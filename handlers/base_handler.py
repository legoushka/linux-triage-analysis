from abc import ABC, abstractmethod
from typing import Dict, Any, List
import os
from config import AUTH_LOG_PATHS, RESULTS_DIR

class BaseHandler(ABC):
    @classmethod
    @abstractmethod
    def can_handle(cls, logsource: Dict[str, Any]) -> bool:
        pass

    @classmethod
    @abstractmethod
    def parse_rule(cls, detection: Dict[str, Any]):
        pass

    @abstractmethod
    def check(self, vm_path: str, rule) -> List[str]:
        pass

    def _find_auth_log(self, vm_path: str) -> str:
        for log_path in AUTH_LOG_PATHS:
            full_path = os.path.join(vm_path, log_path)
            if os.path.exists(full_path):
                return full_path
        return None