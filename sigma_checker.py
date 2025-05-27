import os
import yaml
import sys
import tarfile
from collections import defaultdict
from config import SIGMA_RULES_DIR, RESULTS_DIR
import argparse
import logging
from datetime import datetime
from termcolor import colored
from typing import Dict, List, Tuple, Any
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from sigma.schema import Rule, RuleLevel
from sigma.errors import RuleValidationError, ConditionSyntaxError

from handlers import (
    NetworkConnectionHandler,
    SSHDLogHandler,
    PrivilegedUserHandler,
    BashHistoryHandler,
    ApacheAccessHandler
)
from report_generator import generate_pdf_report
from log_translations import get_log_translation

HANDLERS = [
    NetworkConnectionHandler,
    SSHDLogHandler,
    PrivilegedUserHandler,
    BashHistoryHandler,
    ApacheAccessHandler
]

def setup_logger(verbose: bool = False):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Format for file log
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File logger
    file_handler = logging.FileHandler('triage.log')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console logger
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(logging.Formatter(colored('%(message)s', 'white')))
    logger.addHandler(console_handler)

def unarchive_results(lang: str = 'ru'):
    """Recursively unarchive any .tar.gz files in the results directory and its subdirectories."""
    logging.info(colored(get_log_translation('checking_archives', lang), 'blue'))
    yes_for_all = False
    no_for_all = False
    
    for dirpath, dirnames, filenames in os.walk(RESULTS_DIR):
        for filename in filenames:
            if filename.endswith('.tar.gz'):
                archive_path = os.path.join(dirpath, filename)
                existing = [f for f in os.listdir(dirpath) if f != filename]
                if existing:
                    if not yes_for_all and not no_for_all:
                        print(colored(get_log_translation('archive_found', lang, archive_path), 'yellow'))
                        print(colored(get_log_translation('dir_contains_files', lang, dirpath, existing), 'yellow'))
                        print(get_log_translation('extraction_options', lang))
                        answer = input(get_log_translation('extraction_prompt', lang)).strip().lower()
                        if answer == 'a':
                            yes_for_all = True
                        elif answer == 'na':
                            no_for_all = True
                        elif answer == 'y' or answer == 'yes':
                            pass
                        else:
                            logging.info(get_log_translation('skipping_extraction', lang, archive_path))
                            continue
                    if yes_for_all or (not no_for_all and (answer == 'y' or answer == 'yes')):
                        for f in existing:
                            full_path = os.path.join(dirpath, f)
                            try:
                                if os.path.isdir(full_path):
                                    import shutil
                                    shutil.rmtree(full_path)
                                else:
                                    os.remove(full_path)
                            except Exception as e:
                                logging.error(get_log_translation('extraction_error', lang, filename, dirpath, str(e)))
                        logging.info(get_log_translation('cleared_dir', lang, dirpath, filename))
                        try:
                            with tarfile.open(archive_path, 'r:gz') as tar:
                                tar.extractall(path=dirpath)
                        except Exception as e:
                            logging.error(get_log_translation('extraction_error', lang, filename, dirpath, str(e)))
                    elif no_for_all or (not yes_for_all and (answer == 'n' or answer == 'no' or answer == '')):
                        logging.info(get_log_translation('skipping_extraction', lang, archive_path))
                        continue
                else:
                    try:
                        with tarfile.open(archive_path, 'r:gz') as tar:
                            tar.extractall(path=dirpath)
                        logging.info(get_log_translation('extraction_success', lang, filename, dirpath))
                    except Exception as e:
                        logging.error(get_log_translation('extraction_error', lang, filename, dirpath, str(e)))

def load_sigma_rules(lang: str = 'ru') -> List[Tuple[Rule, Any]]:
    rules = []
    logging.info(colored(get_log_translation('loading_rules', lang), 'blue'))
    
    for rule_file in os.listdir(SIGMA_RULES_DIR):
        if not rule_file.endswith(('.yml', '.yaml')):
            continue
        
        path = os.path.join(SIGMA_RULES_DIR, rule_file)
        try:
            rule = Rule.from_yaml(path)
            logging.debug(get_log_translation('processing_rule', lang, rule_file))

            for handler_class in HANDLERS:
                if handler_class.can_handle(rule.logsource.dict()):
                    config = handler_class.parse_rule(rule.detection.dict())
                    rules.append((rule, handler_class(config)))
                    logging.info(get_log_translation('rule_loaded', lang, rule.title, rule.id))
                    break
            else:
                logging.warning(get_log_translation('no_handler', lang, rule_file))
                
        except (RuleValidationError, ConditionSyntaxError) as e:
            logging.error(get_log_translation('validation_error', lang, rule_file, str(e)))
        except Exception as e:
            logging.error(get_log_translation('loading_error', lang, rule_file, str(e)))
    
    logging.info(get_log_translation('total_rules', lang, len(rules)))
    return rules

def scan_vms(rules: List[Tuple[Rule, Any]], lang: str = 'ru') -> Dict[str, Dict[str, List[str]]]:
    results = defaultdict(lambda: defaultdict(list))
    vm_list = [d for d in os.listdir(RESULTS_DIR) if os.path.isdir(os.path.join(RESULTS_DIR, d))]
    
    logging.info(get_log_translation('scanning_vms', lang))
    logging.info(get_log_translation('found_vms', lang, len(vm_list), ', '.join(vm_list)))
    
    for vm in vm_list:
        vm_path = os.path.join(RESULTS_DIR, vm)
        logging.info(get_log_translation('scanning_vm', lang, vm))
        
        for rule_number, (rule, handler) in enumerate(rules, start=1):
            try:
                findings = handler.check(vm_path, rule, rule_number)
                if findings:
                    results[rule.id][vm].extend(findings)
                    logging.debug(get_log_translation('found_events', lang, len(findings), rule.title))
            except Exception as e:
                logging.error(get_log_translation('rule_check_error', lang, rule.id, vm, str(e)))
    
    return results

def print_statistics(results: Dict[str, Dict[str, List[str]]], rules: List[Tuple[Rule, Any]], verbose: bool = False, lang: str = 'ru'):
    summary = []
    
    vm_stats = defaultdict(lambda: {
        'rules': defaultdict(int),
        'criticality': defaultdict(int),
        'rule_titles': defaultdict(list)
    })
    
    rules_map = {rule.id: rule for rule, _ in rules}
    
    for rule_id, vm_data in results.items():
        rule = rules_map[rule_id]
        for vm, findings in vm_data.items():
            vm_stats[vm]['rules'][rule_id] += len(findings)
            vm_stats[vm]['criticality'][rule.level] += 1
            vm_stats[vm]['rule_titles'][rule_id].append({
                'title': rule.title,
                'count': len(findings)
            })

    if verbose:
        for rule_id, vm_data in results.items():
            rule = rules_map[rule_id]
            color = 'red' if rule.level == RuleLevel.HIGH else 'yellow' if rule.level == RuleLevel.MEDIUM else 'cyan'
            summary.append(colored(f"\nRule: {rule.title} ({rule_id})", color))

            for vm, findings in vm_data.items():
                examples = '\n    '.join(findings[:3])
                summary.append(f"  {vm}: {len(findings)} findings")
                summary.append(f"    Examples:\n    {examples}")
    else:
        summary.append(colored(get_log_translation('compact_summary', lang), 'green'))
        for vm, data in vm_stats.items():
            rule_entries = []
            for rule_id, count in data['rules'].items():
                rule = rules_map[rule_id]
                color = 'red' if rule.level == RuleLevel.HIGH else 'yellow' if rule.level == RuleLevel.MEDIUM else 'cyan'
                title = f"{rule.title} ({count})"
                rule_entries.append(colored(title, color))
            
            rules_str = ', '.join(rule_entries)
            summary.append(
                colored(f"{vm.ljust(15)}", 'white') + 
                colored(get_log_translation('detected', lang), 'cyan') + 
                rules_str
            )

    print('\n'.join(summary))
    with open('triage_summary.txt', 'w') as f:
        f.write('\n'.join(summary))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--pdf', action='store_true', help='Generate PDF report')
    parser.add_argument('--lang', choices=['en', 'ru'], default='ru', help='Report language (default: ru)')
    args = parser.parse_args()
    
    setup_logger(args.verbose)
    
    try:
        logging.info(colored(get_log_translation('triage_started', args.lang, datetime.now().strftime('%Y-%m-%d %H:%M:%S')), 'blue'))
        
        unarchive_results(args.lang)
        
        rules = load_sigma_rules(args.lang)
        if not rules:
            logging.error(colored(get_log_translation('no_rules', args.lang), 'red'))
            return
        
        results = scan_vms(rules, args.lang)
        print_statistics(results, rules, args.verbose, args.lang)
        
        if args.pdf:
            generate_pdf_report(results, rules, args.verbose, args.lang)
        
    except Exception as e:
        logging.error(colored(get_log_translation('fatal_error', args.lang, str(e)), 'red'))
    finally:
        logging.info(colored(get_log_translation('triage_completed', args.lang, datetime.now().strftime('%Y-%m-%d %H:%M:%S')), 'blue'))

if __name__ == "__main__":
    main()