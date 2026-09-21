#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Embedded OCR AI Auto-Healer Engine (embedded_ocr_heal.py)
Inspired by Alibaba Open Code Review (OCR) heal_code capability.
Reads 'ai_heal_instructions' from report_ocr_gate.json (or sub-reports),
generates deterministic surgical C code patches, applies them safely with backups,
and optionally re-runs the OCR gate to verify the self-healing loop.

Supported Auto-Heal Actions:
- ADD_VOLATILE_QUALIFIER: Inserts 'volatile' into ISR-shared variable declarations.
- ADD_F_SUFFIX: Appends 'f' to floating-point numeric constants (e.g. 0.1 -> 0.1f).
- USE_FLOAT_MATH_FUNC: Replaces double math functions with single-precision 'f' variants.
- REPLACE_DOUBLE_WITH_FLOAT: Replaces 'double' keyword with 'float'.
- INITIALIZE_VARIABLE: Safely initializes uninitialized local variables to 0 or NULL.
- REFACTOR_STACK_ARRAY_TO_STATIC: Converts stack-exploding local arrays to static storage.
"""

import os
import sys
import re
import json
import difflib
import shutil
import argparse
import subprocess
from pathlib import Path

# Ensure UTF-8 output on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass


def color_diff(diff_lines):
    """Format unified diff with ANSI colors for console."""
    formatted = []
    for line in diff_lines:
        if line.startswith('+') and not line.startswith('+++'):
            formatted.append(f"\033[32m{line}\033[0m")
        elif line.startswith('-') and not line.startswith('---'):
            formatted.append(f"\033[31m{line}\033[0m")
        elif line.startswith('^') or line.startswith('@@'):
            formatted.append(f"\033[36m{line}\033[0m")
        else:
            formatted.append(line)
    return '\n'.join(formatted)


class CodeHealer:
    def __init__(self, workspace_dir, dry_run=True, create_backup=True):
        self.workspace = Path(workspace_dir).resolve()
        self.dry_run = dry_run
        self.create_backup = create_backup
        # file_path -> list of modified lines
        self.file_cache = {}
        self.original_cache = {}
        self.healed_count = 0
        self.skipped_count = 0

    def load_file(self, file_path):
        norm = os.path.normpath(file_path)
        if norm not in self.file_cache:
            with open(norm, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            self.file_cache[norm] = list(lines)
            self.original_cache[norm] = list(lines)
        return self.file_cache[norm]

    def heal_task(self, task):
        action = task.get('action')
        file_path = task.get('full_path') or task.get('file')
        line_no = task.get('line')

        if not file_path:
            return False

        if not os.path.isabs(file_path):
            file_path = str(self.workspace / file_path)

        if not os.path.exists(file_path):
            return False

        lines = self.load_file(file_path)
        if line_no is None or line_no < 1 or line_no > len(lines):
            return False

        idx = line_no - 1
        orig_line = lines[idx]
        new_line = orig_line

        if action == 'ADD_VOLATILE_QUALIFIER':
            var_name = task.get('variable')
            # Look for declaration on or around this line
            # E.g., 'uint8_t TabBuf[...];' -> 'volatile uint8_t TabBuf[...];'
            # Or 'extern uint8_t TabBuf;' -> 'extern volatile uint8_t TabBuf;'
            if 'volatile' not in orig_line:
                if orig_line.strip().startswith('extern '):
                    new_line = re.sub(r'\bextern\s+', 'extern volatile ', orig_line, count=1)
                else:
                    # Insert volatile before first type token
                    indent = len(orig_line) - len(orig_line.lstrip())
                    indent_str = orig_line[:indent]
                    rest = orig_line[indent:]
                    new_line = indent_str + 'volatile ' + rest

        elif action == 'ADD_F_SUFFIX':
            target_lit = task.get('target')
            if target_lit and target_lit in orig_line:
                # Replace literal that doesn't have f after it
                pattern = re.compile(r'(?<![A-Za-z0-9_\.])(' + re.escape(target_lit) + r')(?![fFA-Za-z0-9_\.])')
                new_line = pattern.sub(r'\1f', orig_line)

        elif action == 'USE_FLOAT_MATH_FUNC':
            target_func = task.get('target')
            if target_func and (target_func + '(') in orig_line:
                pattern = re.compile(r'\b' + re.escape(target_func) + r'\s*\(')
                new_line = pattern.sub(f'{target_func}f(', orig_line)

        elif action == 'REPLACE_DOUBLE_WITH_FLOAT':
            if 'double' in orig_line:
                new_line = re.sub(r'\bdouble\b', 'float', orig_line)

        elif action == 'INITIALIZE_VARIABLE':
            var_name = task.get('variable')
            if var_name and var_name in orig_line:
                # E.g. 'uint32_t status;' -> 'uint32_t status = 0;'
                # Or 'char *ptr;' -> 'char *ptr = NULL;'
                pattern = re.compile(r'\b' + re.escape(var_name) + r'\s*;')
                init_val = '= NULL;' if '*' in orig_line else '= 0;'
                new_line = pattern.sub(f'{var_name} {init_val}', orig_line)

        elif action == 'REFACTOR_STACK_ARRAY_TO_STATIC':
            # E.g. 'uint8_t buf[4096];' -> 'static uint8_t buf[4096];'
            if 'static' not in orig_line:
                indent = len(orig_line) - len(orig_line.lstrip())
                indent_str = orig_line[:indent]
                rest = orig_line[indent:]
                new_line = indent_str + 'static ' + rest

        elif action == 'WRAP_ENDIAN_SWAP':
            pref_swap = task.get('pref_swap', 'SwapU16')
            # E.g. 'psDDMTab->MonTemp = stRtDDM.MonTemp;' -> 'psDDMTab->MonTemp = SwapU16(stRtDDM.MonTemp);'
            if '=' in orig_line and ';' in orig_line:
                left_side, right_side = orig_line.split('=', 1)
                clean_rhs = right_side.strip().rstrip(';')
                if not any(sw in clean_rhs for sw in ['Swap', '__REV', 'htons']):
                    new_line = left_side + f'= {pref_swap}({clean_rhs.strip()});\n'

        elif action == 'CONVERT_TO_BITWISE_OR':
            # E.g. 'SffLow[bsAddr + i] = g_StatFlgs[i];' -> 'SffLow[bsAddr + i] |= g_StatFlgs[i];'
            if '=' in orig_line and '==' not in orig_line and '!=' not in orig_line and '|=' not in orig_line:
                new_line = re.sub(r'(?<![|<>=!&+-])\s*=\s*(?!=)', ' |= ', orig_line, count=1)

        elif action == 'ADD_I2C_BUSY_GUARD':
            # Insert 'wait_i2c_busy();' before modifying shared shadow registers or calling UpdtIntL
            indent = len(orig_line) - len(orig_line.lstrip())
            indent_str = orig_line[:indent]
            new_line = indent_str + 'wait_i2c_busy();\n' + orig_line

        elif action == 'ISOLATE_FLASH_FROM_I2C':
            # Wrap Flash operation with mcu_i2cs_en(0)
            indent = len(orig_line) - len(orig_line.lstrip())
            indent_str = orig_line[:indent]
            new_line = indent_str + 'mcu_i2cs_en(0);\n' + orig_line

        if new_line != orig_line:
            lines[idx] = new_line
            self.healed_count += 1
            return True
        else:
            self.skipped_count += 1
            return False

    def save_all(self):
        """Save modified files to disk, creating backups if requested."""
        modified_files = []
        for file_path, new_lines in self.file_cache.items():
            orig_lines = self.original_cache[file_path]
            if new_lines != orig_lines:
                modified_files.append(file_path)
                if not self.dry_run:
                    if self.create_backup:
                        bak_path = file_path + '.bak'
                        shutil.copyfile(file_path, bak_path)
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.writelines(new_lines)
        return modified_files

    def get_diffs(self):
        """Generate unified diffs across all modified files."""
        diffs = {}
        for file_path, new_lines in self.file_cache.items():
            orig_lines = self.original_cache[file_path]
            if new_lines != orig_lines:
                rel_path = os.path.relpath(file_path, self.workspace).replace('\\', '/')
                diff = list(difflib.unified_diff(
                    orig_lines, new_lines,
                    fromfile=f"a/{rel_path}",
                    tofile=f"b/{rel_path}"
                ))
                diffs[rel_path] = diff
        return diffs


def main():
    parser = argparse.ArgumentParser(description="Embedded OCR AI Auto-Healer Engine")
    parser.add_argument('--workspace', required=True, help="Path to firmware workspace")
    parser.add_argument('--report', default=None, help="Path to JSON report containing ai_heal_instructions")
    parser.add_argument('--rule', default=None, help="Heal only tasks matching this rule_id")
    parser.add_argument('--apply', action='store_true', help="Apply patches to disk (default is dry-run)")
    parser.add_argument('--no-backup', action='store_true', help="Do not create .bak files before applying")
    parser.add_argument('--retest', action='store_true', help="Re-run embedded_ocr_gate.py after applying to verify")
    args = parser.parse_args()

    workspace_dir = Path(args.workspace).resolve()

    # Determine report path
    if args.report:
        report_path = Path(args.report).resolve()
    else:
        report_path = workspace_dir / 'reports' / 'report_ocr_gate.json'

    if not report_path.exists():
        # Fallback to sub-reports if unified doesn't exist
        for cand_name in ['report_concurrency.json', 'report_float.json', 'report_timeout.json', 'report_cppcheck.json']:
            cand = workspace_dir / 'reports' / cand_name
            if cand.exists():
                report_path = cand
                break

    if not report_path.exists():
        print(f"\n❌ [Auto-Heal Error] No OCR JSON report found at: {report_path}")
        print("Run 'embedded_ocr_gate.py' or an analyzer first to generate the report!\n")
        sys.exit(1)

    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"\n❌ [Auto-Heal Error] Failed to read report JSON: {e}\n")
        sys.exit(1)

    tasks = data.get('ai_heal_instructions', [])
    if not tasks:
        print("\n✅ [Auto-Heal] No pending 'ai_heal_instructions' found in report. Codebase is already clean!\n")
        sys.exit(0)

    if args.rule:
        tasks = [t for t in tasks if t.get('rule_id') == args.rule]

    is_dry_run = not args.apply
    healer = CodeHealer(workspace_dir, dry_run=is_dry_run, create_backup=not args.no_backup)

    print("\n" + "=" * 70)
    print(f"🤖 Embedded OCR AI Auto-Healer Engine ({'DRY-RUN' if is_dry_run else 'APPLY MODE'})")
    print(f"📁 Report Ingested: {report_path}")
    print(f"📋 Total Tasks to Heal: {len(tasks)}")
    print("=" * 70 + "\n")

    for task in tasks:
        healer.heal_task(task)

    diffs = healer.get_diffs()

    if not diffs:
        print("⚠️ No applicable changes were generated.")
        sys.exit(0)

    for rel_path, diff_lines in diffs.items():
        print(f"--- Patches for: {rel_path} ---")
        diff_str = "".join(diff_lines)
        if sys.platform == 'win32' and os.isatty(sys.stdout.fileno()):
            print(color_diff(diff_lines))
        else:
            print(diff_str)
        print()

    print("-" * 70)
    print(f"🎯 Auto-Heal Summary: {healer.healed_count} issue(s) patched across {len(diffs)} file(s).")
    if is_dry_run:
        print("🛡️ Dry-run mode active. No source files were touched.")
        print("👉 Pass '--apply' to write these patches to disk safely (with automatic .bak backups).")
    else:
        modified = healer.save_all()
        print(f"💾 Applied changes to {len(modified)} file(s) with .bak backups.")

        if args.retest:
            print("\n🔄 Re-testing with embedded_ocr_gate.py...")
            gate_script = Path(__file__).resolve().parent / 'embedded_ocr_gate.py'
            cmd = [sys.executable, str(gate_script), '--workspace', str(workspace_dir)]
            res = subprocess.run(cmd)
            sys.exit(res.returncode)

    print("=" * 70 + "\n")


if __name__ == '__main__':
    main()

