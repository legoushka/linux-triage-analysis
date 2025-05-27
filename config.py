import os

BASE_DIR = "/home/user/triage"
SIGMA_RULES_DIR = os.path.join(BASE_DIR, "sigma_rules")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
AUTH_LOG_PATHS = [
    '[root]/var/log/auth.log',       # Для Debian
    '[root]/var/log/secure',         # Для RHEL
]

# List of possible ss output files for network connection analysis (ordered by preference)
SS_OUTPUT_FILES = [
    'ss_-tanp.txt'
]

# List of possible .bash_history file paths (relative to VM root)
BASH_HISTORY_PATHS = [
    '[root]/root/.bash_history',
    '[root]/home/user/.bash_history',
]

APACHE_ACCESS_LOG_PATHS = [
    '[root]/var/log/apache2/access.log',
]