import logging
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Any
from termcolor import colored

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import cidfonts

from sigma.schema import Rule, RuleLevel

import os
from config import RESULTS_DIR # Import RESULTS_DIR

# Register ArialMT font for Cyrillic support
FONT_PATH = os.path.join(os.path.dirname(__file__), "fonts", "arialmt.ttf")
pdfmetrics.registerFont(TTFont("ArialMT", FONT_PATH))

# Translations dictionary
TRANSLATIONS = {
    'ru': {
        'title': 'Отчет о сканировании',
        'generated_on': 'Сгенерировано',
        'summary': 'Сводка',
        'detailed_findings': 'Подробные результаты',
        'vm': 'ВМ',
        'high_risk': 'Высокий риск',
        'medium_risk': 'Средний риск',
        'low_risk': 'Низкий риск',
        'total_findings': 'Всего находок',
        'rule': 'Правило',
        'id': 'ID',
        'level': 'Уровень',
        'number_of_findings': 'Количество находок',
        'findings': 'Находки',
        'pdf_generated': '✓ PDF отчет сгенерирован: triage_report.pdf'
    },
    'en': {
        'title': 'Triage Scan Report',
        'generated_on': 'Generated on',
        'summary': 'Summary',
        'detailed_findings': 'Detailed Findings',
        'vm': 'VM',
        'high_risk': 'High Risk',
        'medium_risk': 'Medium Risk',
        'low_risk': 'Low Risk',
        'total_findings': 'Total Findings',
        'rule': 'Rule',
        'id': 'ID',
        'level': 'Level',
        'number_of_findings': 'Number of findings',
        'findings': 'Findings',
        'pdf_generated': '✓ PDF report generated: triage_report.pdf'
    }
}

def get_translation(key: str, lang: str = 'ru') -> str:
    """Get translation for a key in the specified language, fallback to English if not found."""
    return TRANSLATIONS.get(lang, TRANSLATIONS['en']).get(key, TRANSLATIONS['en'][key])

def get_or_create_style(styles, name, parent=None, **kwargs):
    """Get existing style or create a new one if it doesn't exist."""
    if name in styles:
        return styles[name]
    kwargs['fontName'] = "ArialMT"
    styles.add(ParagraphStyle(name=name, parent=parent, **kwargs))
    return styles[name]

def generate_pdf_report(results: Dict[str, Dict[str, List[str]]], rules: List[Tuple[Rule, Any]], verbose: bool = False, lang: str = 'ru'):
    """Generate a PDF report of the scan results."""
    logging.debug(f"Generating PDF report. Results: {results}") # Debug log for results

    doc = SimpleDocTemplate(
        "triage_report.pdf",
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    # Create custom styles
    styles = getSampleStyleSheet()
    # Define custom styles with ArialMT for all text
    my_title = get_or_create_style(styles, 'MyTitle', None, fontSize=24, spaceAfter=30, alignment=1)
    my_heading1 = get_or_create_style(styles, 'MyHeading1', None, fontSize=16, spaceAfter=12, alignment=1)
    my_heading2 = get_or_create_style(styles, 'MyHeading2', None, fontSize=14, spaceAfter=8, alignment=0)
    my_heading3 = get_or_create_style(styles, 'MyHeading3', None, fontSize=12, spaceAfter=6, alignment=0)
    my_normal = get_or_create_style(styles, 'MyNormal', None, fontSize=10, spaceAfter=6, alignment=0)
    my_finding = get_or_create_style(styles, 'MyFinding', None, fontSize=9, leftIndent=20, spaceAfter=4, alignment=0)
    
    # Create a mapping of rule IDs to rule objects for quick lookup
    rules_map = {rule.id: rule for rule, _ in rules}
    
    # Build the document content
    story = []
    
    # Title
    story.append(Paragraph(get_translation('title', lang), my_title))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"{get_translation('generated_on', lang)}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", my_normal))
    story.append(Spacer(1, 24))
    
    # Summary section
    story.append(Paragraph(get_translation('summary', lang), my_heading1))
    story.append(Spacer(1, 12))
    
    # Group by VM
    vm_stats = defaultdict(lambda: {
        'rules': defaultdict(int),
        'criticality': defaultdict(int)
    })
    
    # Get list of all VMs scanned by listing directories in RESULTS_DIR
    all_vms = [d for d in os.listdir(RESULTS_DIR) if os.path.isdir(os.path.join(RESULTS_DIR, d))]
    logging.debug(f"All scanned VMs: {all_vms}") # Debug log for all_vms

    # Initialize vm_stats for all VMs with zero findings
    for vm in all_vms:
        vm_stats[vm] = {
            'rules': defaultdict(int),
            'criticality': defaultdict(int)
        }

    # Populate vm_stats with actual findings by iterating through results
    for rule_id, vm_data in results.items():
        rule = rules_map[rule_id]
        for vm, findings in vm_data.items():
            # Only update stats for VMs with findings (already initialized to zero for all VMs)
            vm_stats[vm]['rules'][rule_id] += len(findings)
            vm_stats[vm]['criticality'][rule.level] += 1
    
    logging.debug(f"VM stats after populating: {vm_stats}") # Debug log for vm_stats

    
    # Create summary table
    summary_data = [[
        get_translation('vm', lang),
        get_translation('high_risk', lang),
        get_translation('medium_risk', lang),
        get_translation('low_risk', lang),
        get_translation('total_findings', lang)
    ]]
    
    # Sort VMs alphabetically for consistent report generation
    sorted_vms = sorted(vm_stats.keys())
    
    for vm in sorted_vms:
        data = vm_stats[vm]
        high = data['criticality'].get(RuleLevel.HIGH, 0)
        medium = data['criticality'].get(RuleLevel.MEDIUM, 0)
        low = data['criticality'].get(RuleLevel.LOW, 0)
        total = sum(data['rules'].values())
        summary_data.append([vm, str(high), str(medium), str(low), str(total)])
    
    logging.debug(f"Summary table data: {summary_data}") # Debug log for summary_data

    # Adjust column widths
    summary_table = Table(summary_data, colWidths=[1.5*inch, 1.1*inch, 1.1*inch, 1.1*inch, 1.2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'ArialMT'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'ArialMT'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 24))
    
    # Detailed findings
    story.append(Paragraph(get_translation('detailed_findings', lang), my_heading1))
    story.append(Spacer(1, 12))
    
    for rule_id, vm_data in results.items():
        rule = rules_map[rule_id]
        story.append(Paragraph(f"{get_translation('rule', lang)}: {rule.title}", my_heading2))
        story.append(Paragraph(f"{get_translation('id', lang)}: {rule_id}", my_normal))
        story.append(Paragraph(f"{get_translation('level', lang)}: {rule.level}", my_normal))
        story.append(Spacer(1, 12))
        
        for vm, findings in vm_data.items():
            story.append(Paragraph(f"{get_translation('vm', lang)}: {vm}", my_heading3))
            story.append(Paragraph(f"{get_translation('number_of_findings', lang)}: {len(findings)}", my_normal))
            
            # Add all findings
            if findings:
                story.append(Paragraph(f"{get_translation('findings', lang)}:", my_normal))
                for finding in findings:
                    story.append(Paragraph(f"• {finding}", my_finding))
            
            story.append(Spacer(1, 12))
        
        # Add page break between rules for better readability
        story.append(PageBreak())
    
    # Build the PDF
    doc.build(story)
    logging.info(colored(get_translation('pdf_generated', lang), 'green')) 