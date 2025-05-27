from typing import Dict

LOG_TRANSLATIONS: Dict[str, Dict[str, str]] = {
    'ru': {
        'triage_started': '=== Триаж начат в {} ===',
        'triage_completed': '=== Триаж завершен в {} ===',
        'checking_archives': '=== Проверка архивов результатов ===',
        'archive_found': '\nНайден архив: {}',
        'dir_contains_files': 'Директория {} уже содержит извлеченные файлы: {}',
        'extraction_options': 'Опции: [y]es, [n]o, [A]ll yes, [NA]ll no',
        'extraction_prompt': 'Хотите очистить папку (кроме архива) и извлечь снова? [y/N/A/NA]: ',
        'skipping_extraction': 'Пропуск извлечения для {}',
        'cleared_dir': 'Очищена {}, извлечение {}',
        'extraction_success': '✓ Успешно извлечен {} в {}',
        'extraction_error': '❌ Ошибка извлечения {} в {}: {}',
        'loading_rules': '=== Загрузка правил Sigma ===',
        'processing_rule': '\nОбработка правила: {}',
        'rule_loaded': '✓ Загружено: {} (ID: {})',
        'no_handler': '⚠ Нет обработчика для правила: {}',
        'validation_error': '❌ Ошибка валидации в {}: {}',
        'loading_error': '❌ Ошибка загрузки {}: {}',
        'total_rules': '\nВсего загружено правил: {}',
        'scanning_vms': '=== Сканирование виртуальных машин ===',
        'found_vms': 'Найдено {} ВМ: {}',
        'scanning_vm': '\nСканирование ВМ: {}',
        'found_events': 'Найдено {} событий для правила {}',
        'rule_check_error': 'Ошибка проверки правила {} на {}: {}',
        'no_rules': 'Не найдено действительных правил!',
        'fatal_error': 'Критическая ошибка: {}',
        'compact_summary': '\n=== Краткая сводка ===',
        'detected': '| Обнаружено: '
    },
    'en': {
        'triage_started': '=== Triage started at {} ===',
        'triage_completed': '=== Triage completed at {} ===',
        'checking_archives': '=== Checking for archived results ===',
        'archive_found': '\nArchive found: {}',
        'dir_contains_files': 'Directory {} already contains extracted files: {}',
        'extraction_options': 'Options: [y]es, [n]o, [A]ll yes, [NA]ll no',
        'extraction_prompt': 'Do you want to clear the folder (except the archive) and extract again? [y/N/A/NA]: ',
        'skipping_extraction': 'Skipping extraction for {}',
        'cleared_dir': 'Cleared {}, extracting {}',
        'extraction_success': '✓ Successfully extracted {} in {}',
        'extraction_error': '❌ Error extracting {} in {}: {}',
        'loading_rules': '=== Loading Sigma Rules ===',
        'processing_rule': '\nProcessing rule: {}',
        'rule_loaded': '✓ Loaded: {} (ID: {})',
        'no_handler': '⚠ No handler for rule: {}',
        'validation_error': '❌ Validation error in {}: {}',
        'loading_error': '❌ Error loading {}: {}',
        'total_rules': '\nTotal rules loaded: {}',
        'scanning_vms': '=== Scanning Virtual Machines ===',
        'found_vms': 'Found {} VMs: {}',
        'scanning_vm': '\nScanning VM: {}',
        'found_events': 'Found {} events for rule {}',
        'rule_check_error': 'Error checking rule {} on {}: {}',
        'no_rules': 'No valid rules found!',
        'fatal_error': 'Fatal error: {}',
        'compact_summary': '\n=== Compact Summary ===',
        'detected': '| Detected: '
    }
}

def get_log_translation(key: str, lang: str = 'ru', *args) -> str:
    """Get translation for a log message in the specified language, fallback to English if not found."""
    translation = LOG_TRANSLATIONS.get(lang, LOG_TRANSLATIONS['en']).get(key, LOG_TRANSLATIONS['en'][key])
    return translation.format(*args) if args else translation 