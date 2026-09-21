#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Embedded Soft-FPU & Float Bloat Sanitizer (float_bloat_analyzer.py)
Audits floating-point bloat and accidental 64-bit double promotion in embedded firmware:
1. [BLOCKER] Explicit 'double' type declarations (Cortex-M4/M0 lacks 64-bit hardware FPU).
2. [CRITICAL] Floating-point numeric literals missing 'f' suffix (e.g., 0.1 instead of 0.1f).
3. [CRITICAL] Invocations of double-precision <math.h> functions (e.g., sin() instead of sinf()).
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

# 64-bit math.h functions that have single-precision 32-bit 'f' counterparts
DOUBLE_MATH_FUNCS = {
    'sin': 'sinf',
    'cos': 'cosf',
    'tan': 'tanf',
    'asin': 'asinf',
    'acos': 'acosf',
    'atan': 'atanf',
    'atan2': 'atan2f',
    'sinh': 'sinhf',
    'cosh': 'coshf',
    'tanh': 'tanhf',
    'exp': 'expf',
    'log': 'logf',
    'log10': 'log10f',
    'pow': 'powf',
    'sqrt': 'sqrtf',
    'ceil': 'ceilf',
    'floor': 'floorf',
    'fabs': 'fabsf',
    'fmod': 'fmodf'
}

DOUBLE_MATH_PATTERN = re.compile(
    r'\b(' + '|'.join(DOUBLE_MATH_FUNCS.keys()) + r')\s*\('
)

# Detect double declaration: double var, double func(...)
EXPLICIT_DOUBLE_PATTERN = re.compile(
    r'\bdouble\b(?!\s*[\*/])'  # Avoid double pointer or comments
)

# Detect floating point literals without f or F suffix: e.g. 0.1, 3.1415, 1e-3, 0.005
# Exclude hex floats or digits followed by f, F, L, l
FLOAT_LITERAL_PATTERN = re.compile(
    r'(?<![A-Za-z0-9_\.])([0-9]+\.[0-9]+(?:[eE][+-]?[0-9]+)?|[0-9]+[eE][+-]?[0-9]+)(?![fFA-Za-z0-9_\.])'
)


def strip_comments_and_strings(text):
    """Strip C comments and literal strings, preserving line breaks."""
    def replacer(match):
        s = match.group(0)
        if s.startswith('/') or s.startswith('"') or s.startswith("'"):
            return '\n' * s.count('\n')
        return s
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)


def analyze_float_in_file(file_path):
    """Analyze a single C/H file for double promotions and missing f suffixes."""
    issues = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return issues

    for idx, line in enumerate(lines, 1):
        # Quick strip single-line comments and strings for line-based scanning
        cleaned_line = re.sub(r'//.*$', '', line)
        cleaned_line = re.sub(r'"(?:\\.|[^\\"])*"', '""', cleaned_line)
        cleaned_line = re.sub(r'/\*.*?\*/', '', cleaned_line)

        # Skip preprocessor includes
        if cleaned_line.strip().startswith('#include'):
            continue

        # 1. Check for explicit 'double'
        if EXPLICIT_DOUBLE_PATTERN.search(cleaned_line):
            issues.append({
                'rule_id': 'EXPLICIT_DOUBLE_DECLARATION',
                'severity': 'BLOCKER',
                'file': os.path.normpath(file_path),
                'line': idx,
                'target': 'double',
                'code_snippet': line.strip(),
                'message': "Explicit 'double' type detected. Cortex-M4/M0 lacks 64-bit hardware FPU, which pulls in soft-float emulation and balloons Flash by 5KB~12KB.",
                'action': 'REPLACE_DOUBLE_WITH_FLOAT',
                'suggested_fix': "Replace 'double' with single-precision 'float'."
            })

        # 2. Check for double math library function calls
        for match in DOUBLE_MATH_PATTERN.finditer(cleaned_line):
            func_name = match.group(1)
            f_counterpart = DOUBLE_MATH_FUNCS[func_name]
            issues.append({
                'rule_id': 'DOUBLE_MATH_LIBRARY_CALL',
                'severity': 'CRITICAL',
                'file': os.path.normpath(file_path),
                'line': idx,
                'target': func_name,
                'code_snippet': line.strip(),
                'message': f"Call to 64-bit double math function '{func_name}()' detected. This bypasses hardware FPU and triggers slow soft-float emulation.",
                'action': 'USE_FLOAT_MATH_FUNC',
                'suggested_fix': f"Replace '{func_name}(...)' with single-precision '{f_counterpart}(...)'."
            })

        # 3. Check for float literals missing 'f' suffix
        for match in FLOAT_LITERAL_PATTERN.finditer(cleaned_line):
            lit = match.group(1)
            # Avoid version macros or ip strings
            if lit.count('.') > 1:
                continue
            issues.append({
                'rule_id': 'FLOAT_LITERAL_MISSING_F_SUFFIX',
                'severity': 'CRITICAL',
                'file': os.path.normpath(file_path),
                'line': idx,
                'target': lit,
                'code_snippet': line.strip(),
                'message': f"Floating-point literal '{lit}' lacks 'f' suffix. C standard treats it as 64-bit double, triggering implicit type promotion and soft-FPU emulation.",
                'action': 'ADD_F_SUFFIX',
                'suggested_fix': f"Append 'f' suffix: change '{lit}' to '{lit}f'."
            })

    return issues


def scan_workspace(workspace_dir, changed_scope=None, include_legacy=False):
    """Scan all C/H files in workspace for float bloat issues."""
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
        issues = analyze_float_in_file(file_path)
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
    """Produce reports/report_float.md and reports/report_float.json."""
    if output_dir:
        out_path = Path(output_dir).resolve()
    else:
        out_path = Path(workspace_dir).resolve() / 'reports'
    out_path.mkdir(parents=True, exist_ok=True)

    md_file = out_path / 'report_float.md'
    json_file = out_path / 'report_float.json'

    # 1. Generate JSON report
    ai_heals = []
    for item in scan_results['new_blockers'] + scan_results['new_critical']:
        rel_path = os.path.relpath(item['file'], workspace_dir).replace('\\', '/')
        ai_heals.append({
            'rule_id': item['rule_id'],
            'file': rel_path,
            'full_path': item['file'].replace('\\', '/'),
            'line': item['line'],
            'target': item['target'],
            'message': item['message'],
            'action': item['action'],
            'instruction': f"Line {item['line']} in {rel_path}: {item['suggested_fix']}"
        })

    json_payload = {
        'gate': gate_verdict,
        'summary': {
            'total_float_hazards_flagged': scan_results['all_issues_count'],
            'new_blockers_count': len(scan_results['new_blockers']),
            'new_critical_count': len(scan_results['new_critical']),
            'legacy_suppressed_count': len(scan_results['legacy_suppressed']),
            'legacy_included_count': len(scan_results['legacy_included'])
        },
        'blockers': scan_results['new_blockers'],
        'critical_issues': scan_results['new_critical'],
        'legacy_suppressed': scan_results['legacy_suppressed'] if not scan_results['legacy_included'] else [],
        'legacy_included': scan_results['legacy_included'],
        'ai_heal_instructions': ai_heals
    }

    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(json_payload, f, indent=2, ensure_ascii=False)

    # 2. Generate Markdown report
    md_lines = [
        "# 📉 嵌入式软浮点与双精度膨胀审计报告 (Soft-FPU & Float Bloat Sanitizer)",
        "",
        f"> [!{'CAUTION' if gate_verdict['verdict'] == 'BLOCKED' else 'NOTE'}]",
        f"> **{gate_verdict['summary']}**",
        "",
        "## 1. 浮点运算架构概览",
        f"- **门禁判定结果**: **`{gate_verdict['verdict']}`** (Exit code: `{gate_verdict['exit_code']}`)",
        f"- **模式**: `{gate_verdict['mode']}`",
        f"- **检测到双精度/软浮点隐患总数**: `{scan_results['all_issues_count']}` 处",
        f"- **🚨 新增阻断级缺陷 (Blockers - explicit double)**: `{len(scan_results['new_blockers'])}` 处",
        f"- **⚠️ 新增高危隐式提升 (Critical - missing f / math calls)**: `{len(scan_results['new_critical'])}` 处",
        f"- **🛡️ 老代码历史问题静默 (Legacy Suppressed)**: `{len(scan_results['legacy_suppressed'])}` 处",
        ""
    ]

    active_issues = scan_results['new_blockers'] + scan_results['new_critical']
    if scan_results['legacy_included']:
        active_issues = active_issues + scan_results['legacy_included']

    if active_issues:
        md_lines.extend([
            "## 2. 🚨 浮点膨胀与性能隐患清单",
            "> [!WARNING]",
            "> 嵌入式 MCU (Cortex-M4/M0) 缺少 64 位双精度硬件 FPU。未带 `f` 的浮点数或 `double` 会强制拉入数 KB 的慢速软模拟库，拖慢 CPU 达 100 倍！",
            "",
            "| 源码文件与行号 | 违规目标 | 规则分类 | 修复加固方案 |",
            "| :--- | :---: | :---: | :--- |"
        ])
        for iss in active_issues:
            rel_path = os.path.relpath(iss['file'], workspace_dir).replace('\\', '/')
            md_lines.append(
                f"| [`{rel_path}:{iss['line']}`](file:///{iss['file'].replace('\\', '/')}#L{iss['line']}) | "
                f"`{iss['target']}` | **{iss['rule_id']}** | {iss['suggested_fix']} |"
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
    parser = argparse.ArgumentParser(description="Embedded Soft-FPU & Float Bloat Sanitizer")
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

