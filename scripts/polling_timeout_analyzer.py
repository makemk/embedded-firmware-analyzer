#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Embedded Hardware Polling Timeout Sanitizer (polling_timeout_analyzer.py)
Audits bare hardware register polling loops in embedded firmware:
1. [CRITICAL] Bare while/do-while polling hardware without timeout counter or watchdog refresh.
Supports human Markdown reports, machine-readable JSON for AI, incremental diff scope, and gate verdicts.
"""

import os
import sys
import re
import json
import argparse
from pathlib import Path
from collections import defaultdict

# Ensure UTF-8 output on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass

script_dir = Path(__file__).resolve().parent
if str(script_dir) not in sys.path:
    sys.path.insert(0, str(script_dir))

from embedded_ocr_common import (
    resolve_changed_scope, is_file_or_line_touched,
    build_gate_verdict, format_ai_heal_instruction
)

# Patterns that indicate a loop condition is checking hardware registers / bus flags
HARDWARE_INDICATOR_PATTERNS = [
    # Member access to status registers
    re.compile(r'->\s*(?:SR|STAT|STATUS|STA|CR|ISR|IFR|RIS|MIS|INTSTA|FLAGS|FLAG|LSR|TCR|FIFO_STA)\b', re.IGNORECASE),
    # Peripheral prefix identifiers (e.g. pADI_I2C0, UART0, SPI1)
    re.compile(r'\b(?:pADI_[A-Za-z0-9_]+|SPI[0-9]*|I2C[0-9]*|UART[0-9]*|USART[0-9]*|ADC[0-9]*|DAC[0-9]*|DMA[0-9]*|CAN[0-9]*|TIMER[0-9]*)\s*->', re.IGNORECASE),
    # Common register flag masks
    re.compile(r'\b(?:[A-Z0-9_]+_(?:FLAG|STATUS|BUSY|READY|RXNE|TXE|TC|BSY|DONE|COMPLETE|TFE|TEMPTY|RXAVAIL))\b'),
    # Direct volatile memory-mapped register access
    re.compile(r'\*(?:__IO|__I|\(volatile|\(volatile\s+[a-zA-Z0-9_]+\s*\*)'),
    # Driver polling helper functions
    re.compile(r'\b(?:[A-Za-z0-9_]+_(?:GetFlagStatus|IsBusy|WaitFlag|ReadStatus|CheckFlag|GetITStatus|Wait_Ready|Poll_[A-Za-z0-9_]+))\s*\('),
]

# Patterns that indicate presence of timeout guard or watchdog refresh
TIMEOUT_GUARD_PATTERNS = [
    re.compile(r'\b(?:timeout|to|time_out|retry|retries|counter|cnt|tick|delay|poll_cnt|loop_cnt)\s*--'),
    re.compile(r'--\s*(?:timeout|to|time_out|retry|retries|counter|cnt|tick|delay|poll_cnt|loop_cnt)\b'),
    re.compile(r'\b(?:timeout|to|time_out|retry|retries|cnt)\s*-='),
    re.compile(r'\b(?:timeout|to|time_out|retry|retries|cnt)\s*==\s*0\b'),
    re.compile(r'\b(?:timeout|to|time_out|retry|retries|cnt)\s*<=\s*0\b'),
    re.compile(r'!\s*(?:timeout|to|time_out|retry|cnt)\b'),
    re.compile(r'\b(?:HAL_GetTick|GetTickCount|systick_get|osKernelGetTickCount|timer_elapsed|sys_now)\s*\('),
    re.compile(r'\b(?:WDT_FEED|IWDG_ReloadCounter|WDT_Clear|feed_watchdog|kick_dog|Watchdog_Refresh)\s*\('),
    re.compile(r'\breturn\s+(?:ERR_TIMEOUT|TIMEOUT|STATUS_TIMEOUT|SYS_ERR_TIMEOUT|-ETIMEDOUT)\b')
]


def strip_comments(text):
    """Strip C comments while preserving line breaks."""
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return '\n' * s.count('\n')
        else:
            return s
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)


def find_matching_bracket(text, start_pos, open_br='{', close_br='}'):
    """Find the closing bracket position corresponding to the opening bracket at start_pos."""
    depth = 0
    in_string = False
    in_char = False
    i = start_pos
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"' and not in_char:
            if i == 0 or text[i - 1] != '\\':
                in_string = not in_string
        elif c == "'" and not in_string:
            if i == 0 or text[i - 1] != '\\':
                in_char = not in_char
        elif not in_string and not in_char:
            if c == open_br:
                depth += 1
            elif c == close_br:
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def analyze_polling_loops_in_file(file_path):
    """
    Parse a C file and detect loops that poll hardware without timeout guards.
    Returns a list of issue dicts.
    """
    issues = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_content = f.read()
    except Exception as e:
        return issues

    clean_content = strip_comments(raw_content)

    # Line offset table for position to line number mapping
    line_starts = [0]
    for m in re.finditer(r'\n', raw_content):
        line_starts.append(m.end())

    def get_line_no(char_idx):
        import bisect
        return bisect.bisect_right(line_starts, char_idx)

    # Regex for finding while (...) loops
    while_pattern = re.compile(r'\bwhile\s*\(\s*(.*?)\s*\)', re.DOTALL)
    for m in while_pattern.finditer(clean_content):
        start_pos = m.start()
        line_no = get_line_no(start_pos)
        cond_text = m.group(1).strip()

        # Check if condition is an infinite loop like while(1) or while(true)
        is_infinite_loop_header = cond_text in ('1', 'true', 'TRUE', '1U', '1UL')

        # Check if condition matches hardware indicators
        is_hw_condition = any(p.search(cond_text) for p in HARDWARE_INDICATOR_PATTERNS)

        # Check loop body
        end_of_header = m.end()
        # Find start of body (either '{' or immediate statement ending with ';')
        body_slice = clean_content[end_of_header:end_of_header + 500]
        body_text = ""
        brace_match = re.search(r'\S', body_slice)
        if brace_match:
            first_char = brace_match.group(0)
            char_pos = end_of_header + brace_match.start()
            if first_char == '{':
                closing_brace_pos = find_matching_bracket(clean_content, char_pos)
                if closing_brace_pos != -1:
                    body_text = clean_content[char_pos:closing_brace_pos + 1]
            elif first_char == ';':
                # Empty body: while (I2C_Busy());
                body_text = ";"
            else:
                # Single statement body: while (I2C_Busy()) delay();
                semi_pos = clean_content.find(';', char_pos)
                if semi_pos != -1:
                    body_text = clean_content[char_pos:semi_pos + 1]

        # In infinite loops like while(1), check if body has hardware polling without timeout
        is_hw_body = any(p.search(body_text) for p in HARDWARE_INDICATOR_PATTERNS)

        if not (is_hw_condition or (is_infinite_loop_header and is_hw_body)):
            continue

        # Now check if there is a timeout guard in condition OR body
        has_timeout = False
        full_loop_scope = cond_text + " " + body_text
        if any(p.search(full_loop_scope) for p in TIMEOUT_GUARD_PATTERNS):
            has_timeout = True

        if not has_timeout:
            # Extract clean snippet
            snippet = cond_text.replace('\n', ' ')
            if len(snippet) > 80:
                snippet = snippet[:77] + '...'

            issues.append({
                'rule_id': 'BARE_HARDWARE_POLLING_WITHOUT_TIMEOUT',
                'severity': 'CRITICAL',
                'file': os.path.normpath(file_path),
                'line': line_no,
                'condition': snippet,
                'message': f"Hardware polling loop 'while({snippet})' lacks a timeout counter or watchdog kick. If the bus hangs or peripheral fails, the MCU will enter an unrecoverable freeze!",
                'action': 'ADD_TIMEOUT_GUARD',
                'suggested_fix': "Wrap loop with a timeout counter: 'uint32_t timeout = 100000; while (...) { if (--timeout == 0) return ERR_TIMEOUT; }'"
            })

    return issues


def scan_workspace(workspace_dir, changed_scope=None, include_legacy=False):
    """Scan all C/H files in workspace for bare polling loops."""
    workspace = Path(workspace_dir).resolve()
    c_files = []
    for root, _, files in os.walk(workspace):
        if any(skip in root.lower() for skip in ['.git', 'node_modules', '.gemini', 'build', 'debug', 'release']):
            continue
        for f in files:
            if f.endswith(('.c', '.h')):
                c_files.append(os.path.join(root, f))

    all_issues = []
    for file_path in c_files:
        issues = analyze_polling_loops_in_file(file_path)
        all_issues.extend(issues)

    new_blockers = []
    new_critical = []
    legacy_suppressed = []
    legacy_included = []

    for issue in all_issues:
        touched = True
        if changed_scope and changed_scope.get('is_incremental'):
            touched = is_file_or_line_touched(issue['file'], issue['line'], changed_scope)

        if touched:
            if issue['severity'] == 'BLOCKER':
                new_blockers.append(issue)
            else:
                new_critical.append(issue)
        else:
            if include_legacy:
                legacy_included.append(issue)
            else:
                legacy_suppressed.append(issue)

    return {
        'all_issues_count': len(all_issues),
        'new_blockers': new_blockers,
        'new_critical': new_critical,
        'legacy_suppressed': legacy_suppressed,
        'legacy_included': legacy_included,
    }


def generate_reports(scan_results, gate_verdict, workspace_dir, output_dir=None):
    """Produce reports/report_timeout.md and reports/report_timeout.json."""
    if output_dir:
        out_path = Path(output_dir).resolve()
    else:
        out_path = Path(workspace_dir).resolve() / 'reports'
    out_path.mkdir(parents=True, exist_ok=True)

    md_file = out_path / 'report_timeout.md'
    json_file = out_path / 'report_timeout.json'

    # 1. Generate JSON report
    ai_heals = []
    for item in scan_results['new_blockers'] + scan_results['new_critical']:
        rel_path = os.path.relpath(item['file'], workspace_dir).replace('\\', '/')
        ai_heals.append({
            'rule_id': item['rule_id'],
            'file': rel_path,
            'full_path': item['file'].replace('\\', '/'),
            'line': item['line'],
            'message': item['message'],
            'action': item['action'],
            'instruction': f"Line {item['line']} in {rel_path} has bare hardware polling 'while({item['condition']})'. {item['suggested_fix']}"
        })

    json_payload = {
        'gate': gate_verdict,
        'summary': {
            'total_polling_loops_flagged': scan_results['all_issues_count'],
            'new_critical_count': len(scan_results['new_critical']),
            'new_blockers_count': len(scan_results['new_blockers']),
            'legacy_suppressed_count': len(scan_results['legacy_suppressed']),
            'legacy_included_count': len(scan_results['legacy_included'])
        },
        'critical_issues': scan_results['new_critical'],
        'blockers': scan_results['new_blockers'],
        'legacy_suppressed': scan_results['legacy_suppressed'] if not scan_results['legacy_included'] else [],
        'legacy_included': scan_results['legacy_included'],
        'ai_heal_instructions': ai_heals
    }

    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(json_payload, f, indent=2, ensure_ascii=False)

    # 2. Generate Markdown report
    md_lines = [
        "# ⏱️ 嵌入式硬件外设状态死等与防死锁审计报告 (Hardware Polling Timeout Gate)",
        "",
        f"> [!{'CAUTION' if gate_verdict['verdict'] == 'BLOCKED' else 'NOTE'}]",
        f"> **{gate_verdict['summary']}**",
        "",
        "## 1. 硬件轮询安全概览",
        f"- **门禁判定结果**: **`{gate_verdict['verdict']}`** (Exit code: `{gate_verdict['exit_code']}`)",
        f"- **模式**: `{gate_verdict['mode']}`",
        f"- **检测到未加超时的裸等循环总数**: `{scan_results['all_issues_count']}` 处",
        f"- **🚨 新增高危裸等缺陷 (Critical)**: `{len(scan_results['new_critical'])}` 处",
        f"- **🛡️ 老代码历史问题静默 (Legacy Suppressed)**: `{len(scan_results['legacy_suppressed'])}` 处",
        ""
    ]

    active_issues = scan_results['new_critical'] + scan_results['new_blockers']
    if scan_results['legacy_included']:
        active_issues = active_issues + scan_results['legacy_included']

    if active_issues:
        md_lines.extend([
            "## 2. 🚨 硬件外设裸等死锁风险清单 (Bare Hardware Polling Loops)",
            "> [!WARNING]",
            "> 以下循环在查询硬件外设/总线状态时缺少超时计数器或看门狗喂狗。一旦总线掉电或被从机拉低，MCU将永久陷入死循环！",
            "",
            "| 源码文件与行号 | 循环判定条件 | 风险类型 | 修复与加固建议 |",
            "| :--- | :--- | :---: | :--- |"
        ])
        for iss in active_issues:
            rel_path = os.path.relpath(iss['file'], workspace_dir).replace('\\', '/')
            md_lines.append(
                f"| [`{rel_path}:{iss['line']}`](file:///{iss['file'].replace('\\', '/')}#L{iss['line']}) | "
                f"`while({iss['condition']})` | **{iss['severity']}** | 包裹超时计数器 (Timeout Guard) |"
            )
        md_lines.append("")

    if ai_heals:
        md_lines.extend([
            "## 3. 🤖 AI 闭环自愈修复指令清单 (Auto-Heal Tasks)",
            ""
        ])
        for idx, task in enumerate(ai_heals, 1):
            md_lines.extend([
                f"### 任务 {idx}: `[{task['rule_id']}]` @ `{task['file']}:{task['line']}`",
                f"- **动作**: `{task['action']}`",
                f"- **自愈指令**: {task['instruction']}",
                ""
            ])

    with open(md_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(md_lines))

    return md_file, json_file


def main():
    parser = argparse.ArgumentParser(description="Embedded Hardware Polling Timeout Sanitizer")
    parser.add_argument('--workspace', required=True, help="Path to firmware workspace")
    parser.add_argument('--changed-files', nargs='*', default=None, help="Specific files changed by AI")
    parser.add_argument('--diff', nargs='?', const='HEAD', default=None, help="Git diff reference")
    parser.add_argument('--include-legacy', action='store_true', help="Include historical legacy issues in report")
    parser.add_argument('--gate', action='store_true', default=True, help="Enable gate mode exit codes")
    parser.add_argument('--output-dir', default=None, help="Directory to store reports")
    parser.add_argument('--no-save', action='store_true', help="Do not save reports to disk")
    args = parser.parse_args()

    changed_scope = resolve_changed_scope(args.workspace, args.changed_files, args.diff)
    scan_results = scan_workspace(args.workspace, changed_scope, args.include_legacy)

    gate_verdict = build_gate_verdict(
        new_blockers=scan_results['new_blockers'],
        critical_issues=scan_results['new_critical'],
        legacy_issues=scan_results['legacy_suppressed'] if not args.include_legacy else scan_results['legacy_included'],
        arch_hazards=[],
        scope=changed_scope
    )

    if not args.no_save:
        md_file, json_file = generate_reports(scan_results, gate_verdict, args.workspace, args.output_dir)
        print(f"\n[Dual Output Generated]")
        print(f"  ├─ Markdown (Human): {md_file}")
        print(f"  └─ JSON (AI):        {json_file}\n")
        try:
            with open(md_file, 'r', encoding='utf-8') as f:
                print(f.read())
        except Exception:
            pass

    sys.exit(gate_verdict['exit_code'])


if __name__ == '__main__':
    main()
