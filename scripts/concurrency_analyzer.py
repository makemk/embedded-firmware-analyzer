#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Embedded ISR & Concurrency Sanitizer (concurrency_analyzer.py)
Audits asynchronous race conditions between Interrupt Service Routines (ISRs)
and the main loop / RTOS tasks in embedded firmware:
1. [BLOCKER] Validates 'volatile' qualification on variables shared between ISR and non-ISR contexts.
2. [CRITICAL] Detects non-atomic shared variables (uint64_t, double, structs) lacking critical section guards.
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


# ==============================================================================
# 1. ISR & Variable Pattern Detection
# ==============================================================================

ISR_NAME_PATTERNS = [
    re.compile(r'\bvoid\s+([A-Za-z0-9_]*(?:IRQHandler|Handler|Int_Handler))\s*\([^)]*\)', re.IGNORECASE),
    re.compile(r'\b__irq\s+void\s+([A-Za-z0-9_]+)\s*\([^)]*\)', re.IGNORECASE),
    re.compile(r'\bvoid\s+([A-Za-z0-9_]+)\s*\([^)]*\)\s*__attribute__\s*\(\s*\(\s*interrupt', re.IGNORECASE),
]

CRITICAL_SECTION_ENTER_PATTERNS = [
    re.compile(r'\b__disable_irq\s*\(\s*\)'),
    re.compile(r'\btaskENTER_CRITICAL\s*\(\s*\)'),
    re.compile(r'\bNVIC_DisableIRQ\s*\('),
    re.compile(r'\b__set_PRIMASK\s*\(\s*1\s*\)'),
    re.compile(r'\bportENTER_CRITICAL\s*\(\s*\)')
]

CRITICAL_SECTION_EXIT_PATTERNS = [
    re.compile(r'\b__enable_irq\s*\(\s*\)'),
    re.compile(r'\btaskEXIT_CRITICAL\s*\(\s*\)'),
    re.compile(r'\bNVIC_EnableIRQ\s*\('),
    re.compile(r'\b__set_PRIMASK\s*\(\s*0\s*\)'),
    re.compile(r'\bportEXIT_CRITICAL\s*\(\s*\)')
]

NON_ATOMIC_TYPES = {
    'uint64_t', 'int64_t', 'unsigned long long', 'long long',
    'double', 'float64_t', 'uint64', 'int64', 'u64', 's64'
}


def find_c_source_files(workspace_dir):
    """Locate all .c and .h files in workspace, skipping build / tool directories."""
    c_files = []
    workspace = Path(workspace_dir).resolve()
    for root, _, files in os.walk(workspace):
        if any(skip in root.lower() for skip in ['.git', 'node_modules', '.gemini', 'build']):
            continue
        for f in files:
            if f.endswith(('.c', '.h')):
                c_files.append(os.path.join(root, f))
    return c_files


def extract_global_variables(files):
    """
    Extract global and file-static variable declarations across files.
    Returns dict: var_name -> {
        "file": str,
        "line": int,
        "type": str,
        "is_volatile": bool,
        "is_non_atomic": bool
    }
    """
    globals_map = {}
    
    # Simple regex for C variable declarations: [static] [volatile] type name [= val];
    decl_re = re.compile(
        r'^(?:extern\s+)?(static\s+)?(const\s+)?(volatile\s+)?([A-Za-z0-9_]+(?:\s*\*+)?)\s+([A-Za-z0-9_]+)\s*(?:\[[^\]]*\])?\s*(?:=[^;]+)?\s*;',
        re.MULTILINE
    )
    
    for f in files:
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
                content = fp.read()
        except Exception:
            continue
            
        # Strip comments
        clean_content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        clean_content = re.sub(r'//.*$', '', clean_content, flags=re.MULTILINE)
        
        # Don't parse inside functions for global declarations
        # Approximate: lines with no leading whitespace or file-level
        lines = clean_content.splitlines()
        brace_depth = 0
        for idx, line in enumerate(lines, 1):
            brace_depth += line.count('{') - line.count('}')
            if brace_depth == 0:
                stripped = line.strip()
                m = decl_re.match(stripped)
                if m:
                    is_const = bool(m.group(2))
                    if is_const:
                        continue  # Read-only constants are race-free
                    is_volatile = bool(m.group(3)) or 'volatile' in stripped
                    var_type = m.group(4).strip()
                    var_name = m.group(5).strip()
                    
                    is_non_atomic = any(t in var_type for t in NON_ATOMIC_TYPES) or '[' in stripped
                    
                    globals_map[var_name] = {
                        "file": f,
                        "line": idx,
                        "type": var_type,
                        "is_volatile": is_volatile,
                        "is_non_atomic": is_non_atomic,
                        "raw_decl": stripped
                    }
                    
    return globals_map


def extract_function_contexts(files):
    """
    Parse functions and classify them into ISR vs Non-ISR contexts,
    and record which global variables are read or written in each function.
    """
    functions = []
    
    for f in files:
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
                lines = fp.readlines()
        except Exception:
            continue
            
        in_func = False
        func_name = None
        func_start_line = 0
        is_isr = False
        func_body = []
        brace_count = 0
        
        for line_idx, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Check function header if not currently inside a function
            if not in_func:
                for pat in ISR_NAME_PATTERNS:
                    m = pat.search(stripped)
                    if m:
                        func_name = m.group(1)
                        is_isr = True
                        in_func = True
                        func_start_line = line_idx
                        func_body = [line]
                        brace_count = line.count('{') - line.count('}')
                        break
                        
                if not in_func and re.match(r'^[A-Za-z0-9_]+\s*(?:\*+)?\s+([A-Za-z0-9_]+)\s*\([^;]*\)\s*\{?', stripped):
                    m = re.match(r'^[A-Za-z0-9_]+\s*(?:\*+)?\s+([A-Za-z0-9_]+)\s*\(', stripped)
                    if m and not any(kw in m.group(1) for kw in ['if', 'while', 'for', 'switch', 'return']):
                        func_name = m.group(1)
                        is_isr = any(kw in func_name for kw in ['Handler', 'IRQHandler', 'ISR', 'Int_Handler'])
                        in_func = True
                        func_start_line = line_idx
                        func_body = [line]
                        brace_count = line.count('{') - line.count('}')
            else:
                func_body.append(line)
                brace_count += line.count('{') - line.count('}')
                if brace_count <= 0 and ('}' in line):
                    functions.append({
                        "name": func_name,
                        "file": f,
                        "start_line": func_start_line,
                        "end_line": line_idx,
                        "is_isr": is_isr,
                        "body": "".join(func_body)
                    })
                    in_func = False
                    func_name = None
                    is_isr = False
                    func_body = []
                    brace_count = 0
                    
    return functions


def analyze_concurrency_hazards(workspace_dir, scope=None):
    """
    Perform deep audit of ISR shared variables, volatile missing, and critical sections.
    """
    files = find_c_source_files(workspace_dir)
    globals_map = extract_global_variables(files)
    functions = extract_function_contexts(files)
    
    isr_funcs = [f for f in functions if f["is_isr"]]
    non_isr_funcs = [f for f in functions if not f["is_isr"]]
    
    # Trace reads/writes of globals
    # var -> {"isr_writes": [...], "isr_reads": [...], "task_writes": [...], "task_reads": [...]}
    usage = defaultdict(lambda: {
        "isr_writes": [], "isr_reads": [],
        "task_writes": [], "task_reads": []
    })
    
    for fn in functions:
        body = fn["body"]
        for var_name in globals_map:
            # Match variable usage as distinct word token
            if re.search(r'\b' + re.escape(var_name) + r'\b', body):
                # Check write pattern: var = ... or var++ or var += or &var
                is_write = bool(re.search(r'\b' + re.escape(var_name) + r'\s*(?:\[[^\]]*\])?\s*(?:[+\-*/&|^]?=|\+\+|--)', body))
                record = {
                    "func": fn["name"],
                    "file": fn["file"],
                    "line": fn["start_line"],
                    "is_write": is_write
                }
                if fn["is_isr"]:
                    if is_write:
                        usage[var_name]["isr_writes"].append(record)
                    else:
                        usage[var_name]["isr_reads"].append(record)
                else:
                    if is_write:
                        usage[var_name]["task_writes"].append(record)
                    else:
                        usage[var_name]["task_reads"].append(record)
                        
    # Detect Concurrency Hazards
    blockers = []
    critical_issues = []
    legacy_suppressed = []
    ai_heal_instructions = []
    safe_shared_vars = []
    
    for var_name, acts in usage.items():
        has_isr_access = len(acts["isr_writes"]) > 0 or len(acts["isr_reads"]) > 0
        has_task_access = len(acts["task_writes"]) > 0 or len(acts["task_reads"]) > 0
        
        # Only analyze variables truly shared across ISR and Task contexts
        if not (has_isr_access and has_task_access):
            continue
            
        var_info = globals_map[var_name]
        is_volatile = var_info["is_volatile"]
        is_non_atomic = var_info["is_non_atomic"]
        is_modified_in_isr = len(acts["isr_writes"]) > 0
        is_read_in_task = len(acts["task_reads"]) > 0
        
        # Check if touched by scope
        var_touched = is_file_or_line_touched(var_info["file"], var_info["line"], scope)
        isr_touched = any(is_file_or_line_touched(x["file"], x["line"], scope) for x in acts["isr_writes"] + acts["isr_reads"])
        task_touched = any(is_file_or_line_touched(x["file"], x["line"], scope) for x in acts["task_writes"] + acts["task_reads"])
        
        touched = var_touched or isr_touched or task_touched
        
        # Rule 1: [BLOCKER] Missing volatile on ISR modified / Task read variable
        if is_modified_in_isr and is_read_in_task and not is_volatile:
            item = {
                "rule_id": "MISSING_VOLATILE_IN_ISR_SHARED_VAR",
                "severity": "BLOCKER",
                "variable": var_name,
                "type": var_info["type"],
                "file": var_info["file"],
                "line": var_info["line"],
                "message": f"Global variable '{var_name}' is modified in ISR but declared without 'volatile'. Compiler optimization (-O2/-O3) can cache it in registers, causing main loop to poll stale values forever!",
                "isr_contexts": [w["func"] for w in acts["isr_writes"]],
                "task_contexts": [r["func"] for r in acts["task_reads"]]
            }
            if touched:
                blockers.append(item)
                ai_heal_instructions.append(format_ai_heal_instruction(
                    "MISSING_VOLATILE_IN_ISR_SHARED_VAR",
                    var_info["file"],
                    var_info["line"],
                    item["message"],
                    "ADD_VOLATILE_QUALIFIER",
                    f"Variable '{var_name}' is written in interrupt '{item['isr_contexts'][0]}' and read in main code. Modify declaration to: 'volatile {var_info['type']} {var_name};'."
                ))
            else:
                legacy_suppressed.append(item)
            continue
            
        # Rule 2: [CRITICAL] Non-atomic shared variable lacking critical section
        if is_non_atomic and (len(acts["isr_writes"]) > 0 or len(acts["task_writes"]) > 0):
            # Check if task functions wrap access in critical section
            has_guard = False
            for tf in non_isr_funcs:
                if var_name in tf["body"]:
                    has_enter = any(p.search(tf["body"]) for p in CRITICAL_SECTION_ENTER_PATTERNS)
                    has_exit = any(p.search(tf["body"]) for p in CRITICAL_SECTION_EXIT_PATTERNS)
                    if has_enter and has_exit:
                        has_guard = True
                        break
                        
            if not has_guard:
                item = {
                    "rule_id": "NON_ATOMIC_SHARED_VARIABLE_TORN_ACCESS",
                    "severity": "CRITICAL",
                    "variable": var_name,
                    "type": var_info["type"],
                    "file": var_info["file"],
                    "line": var_info["line"],
                    "message": f"Non-atomic shared variable '{var_name}' ({var_info['type']}) is read/written across ISR without critical section protection (__disable_irq / taskENTER_CRITICAL). Risk of torn reads/writes!",
                    "isr_contexts": [w["func"] for w in acts["isr_writes"] + acts["isr_reads"]],
                    "task_contexts": [r["func"] for r in acts["task_writes"] + acts["task_reads"]]
                }
                if touched:
                    critical_issues.append(item)
                    ai_heal_instructions.append(format_ai_heal_instruction(
                        "NON_ATOMIC_SHARED_VARIABLE_TORN_ACCESS",
                        var_info["file"],
                        var_info["line"],
                        item["message"],
                        "WRAP_IN_CRITICAL_SECTION",
                        f"Wrap access to '{var_name}' in task context with '__disable_irq(); ... __enable_irq();' or disable the specific IRQ to prevent non-atomic data tearing."
                    ))
                else:
                    legacy_suppressed.append(item)
                continue
                
        safe_shared_vars.append({
            "variable": var_name,
            "type": var_info["type"],
            "is_volatile": is_volatile,
            "file": var_info["file"],
            "line": var_info["line"],
            "isr_count": len(acts["isr_writes"]) + len(acts["isr_reads"]),
            "task_count": len(acts["task_writes"]) + len(acts["task_reads"])
        })
        
    scope_dict = scope or {"is_incremental": False}
    gate = build_gate_verdict(blockers, critical_issues, legacy_suppressed, [], scope_dict)
    
    return {
        "gate": gate,
        "summary": {
            "total_isrs_detected": len(isr_funcs),
            "total_shared_vars": len(safe_shared_vars) + len(blockers) + len(critical_issues),
            "new_blockers_count": len(blockers),
            "new_critical_count": len(critical_issues),
            "legacy_suppressed_count": len(legacy_suppressed)
        },
        "isr_functions": [{"name": f["name"], "file": os.path.basename(f["file"]), "line": f["start_line"]} for f in isr_funcs],
        "blockers": blockers,
        "critical_issues": critical_issues,
        "legacy_suppressed": legacy_suppressed,
        "safe_shared_vars": safe_shared_vars[:15],
        "ai_heal_instructions": ai_heal_instructions
    }


def format_markdown_report(result):
    """Format ISR concurrency analysis results into clean Markdown."""
    lines = []
    lines.append("# ⚡ 嵌入式中断并发与原子性竞态分析报告 (ISR Concurrency Sanitizer)\n")
    
    gate = result.get("gate", {})
    verdict = gate.get("verdict", "PASSED")
    if verdict == "BLOCKED":
        lines.append(f"> [!CAUTION]\n> **🚨 嵌入式 AI 并发竞态门禁拦截 (BLOCKED)**: {gate.get('summary', '')}\n")
    else:
        lines.append(f"> [!NOTE]\n> **✅ 嵌入式 AI 并发竞态门禁通过 (PASSED)**: {gate.get('summary', '')}\n")
        
    summ = result["summary"]
    lines.append("## 1. 中断并发架构概览")
    lines.append(f"- **门禁判定结果**: **`{verdict}`** (Exit code: `{gate.get('exit_code', 0)}`)")
    lines.append(f"- **检测到硬件中断服务函数 (ISR)**: `{summ['total_isrs_detected']}` 个")
    for isr in result.get("isr_functions", []):
        lines.append(f"  - ⚡ `{isr['name']}` @ `{isr['file']}:{isr['line']}`")
    lines.append(f"- **跨中断/主线程共享变量**: `{summ['total_shared_vars']}` 个")
    lines.append(f"- **🚨 新增并发阻断级缺陷 (Missing Volatile)**: `{summ['new_blockers_count']}` 个")
    lines.append(f"- **⚠️ 新增非原子撕裂风险 (Torn Access)**: `{summ['new_critical_count']}` 个")
    if gate.get("is_incremental"):
        lines.append(f"- **🛡️ 老代码历史并发技术债务静默**: `{summ['legacy_suppressed_count']}` 个 (已安全跳过)\n")
        
    # Blockers (Missing volatile)
    blockers = result.get("blockers", [])
    if blockers:
        lines.append("## 2. 🚨 阻断缺陷：ISR 共享变量漏标 `volatile`")
        lines.append("> [!CAUTION]\n> 以下变量在中断中被修改、但在主循环中被读取，由于缺少 `volatile`，编译器开启 `-O2/-O3` 优化后会将变量常驻 CPU 寄存器，引发死循环或数据失效！\n")
        lines.append("| 变量名 | 数据类型 | 声明文件与行号 | 写入的中断 (ISR) | 读取的主线程函数 | 修复建议 |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for b in blockers:
            loc = f"`{os.path.basename(b['file'])}:{b['line']}`"
            isrs = ", ".join(f"`{x}`" for x in b["isr_contexts"][:2])
            tasks = ", ".join(f"`{x}`" for x in b["task_contexts"][:2])
            lines.append(f"| **`{b['variable']}`** | `{b['type']}` | {loc} | {isrs} | {tasks} | 添加 `volatile` 修饰 |")
            
    # Critical Issues (Torn Access)
    crit = result.get("critical_issues", [])
    if crit:
        lines.append("\n## 3. ⚠️ 高危缺陷：非原子类型跨中断撕裂访问 (Torn Read/Write)")
        lines.append("> [!WARNING]\n> 32位 Cortex-M 无法单指令原子读写非32位整型（64位、double、结构体）。若在主循环中无临界区保护读写，会被中断打断拼出物理不存在的错乱数据！\n")
        lines.append("| 变量名 | 类型大小 | 声明位置 | 交叉上下文 | 修复建议 |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for c in crit:
            loc = f"`{os.path.basename(c['file'])}:{c['line']}`"
            lines.append(f"| **`{c['variable']}`** | `{c['type']}` | {loc} | ISR 与 Task 共享 | 包裹 `__disable_irq()` 临界区 |")
            
    # AI Auto-Heal Instructions
    if result.get("ai_heal_instructions"):
        lines.append("\n## 4. 🤖 AI 闭环自愈修复指令清单 (Auto-Heal Tasks)")
        for idx, h in enumerate(result["ai_heal_instructions"], 1):
            lines.append(f"### 任务 {idx}: `[{h['rule_id']}]` @ `{h['file']}:{h['line']}`")
            lines.append(f"- **动作**: `{h['action']}`")
            lines.append(f"- **自愈指令**: {h['instruction']}\n")
            
    # Safe Shared Variables
    safe_vars = result.get("safe_shared_vars", [])
    if safe_vars:
        lines.append("\n## 5. ✅ 已正确修饰与保护的共享变量 (Verified Safe)")
        lines.append("| 变量名 | 数据类型 | volatile 修饰 | 声明文件行号 | 中断访问频次 |")
        lines.append("| :--- | :--- | :---: | :--- | :--- |")
        for sv in safe_vars:
            loc = f"`{os.path.basename(sv['file'])}:{sv['line']}`"
            vol_icon = "✅ 是" if sv["is_volatile"] else "ℹ️ 否 (仅单向/局部)"
            lines.append(f"| `{sv['variable']}` | `{sv['type']}` | {vol_icon} | {loc} | ISR: {sv['isr_count']}, Task: {sv['task_count']} |")
            
    return "\n".join(lines)


def save_dual_reports(output_dir, base_name, md_content, json_data, custom_output=None, no_save=False):
    """Save both human-readable Markdown (.md) and machine-readable JSON (.json) reports."""
    if no_save:
        return None, None
    if custom_output:
        p = Path(custom_output)
        parent_dir = p.parent
        stem = p.stem
        parent_dir.mkdir(parents=True, exist_ok=True)
        md_path = parent_dir / f"{stem}.md"
        json_path = parent_dir / f"{stem}.json"
    else:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        md_path = out_dir / f"{base_name}.md"
        json_path = out_dir / f"{base_name}.json"
        
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
        
    sys.stderr.write(f"\n[Dual Output Generated]\n  ├─ Markdown (Human): {md_path}\n  └─ JSON (AI):        {json_path}\n\n")
    return str(md_path), str(json_path)


def main():
    parser = argparse.ArgumentParser(description="Embedded ISR & Concurrency Sanitizer")
    parser.add_argument("--workspace", "-w", default=".", help="Workspace root directory")
    parser.add_argument("--changed-files", nargs="*", help="Files modified by AI / current commit")
    parser.add_argument("--diff", nargs="?", const="HEAD", help="Use git diff to identify changed scope")
    parser.add_argument("--include-legacy", action="store_true", help="Include legacy technical debt in reports")
    parser.add_argument("--gate", action="store_true", help="Enforce quality gate exit code (1 on blocker)")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Console output format")
    parser.add_argument("--output-dir", help="Directory to save reports (default: <workspace>/reports)")
    parser.add_argument("--output", "-o", help="Custom output path or prefix")
    parser.add_argument("--no-save", action="store_true", help="Do not save reports to disk")
    
    args = parser.parse_args()
    workspace = os.path.abspath(args.workspace)
    
    scope = resolve_changed_scope(workspace, changed_files=args.changed_files, diff_ref=args.diff, include_legacy=args.include_legacy)
    
    res = analyze_concurrency_hazards(workspace, scope)
    
    md_report = format_markdown_report(res)
    reports_dir = args.output_dir or os.path.join(workspace, "reports")
    save_dual_reports(reports_dir, "report_concurrency", md_report, res, args.output, args.no_save)
    
    if args.format == "json":
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        print(md_report)
        
    if args.gate and "gate" in res:
        exit_code = res["gate"].get("exit_code", 0)
        if exit_code != 0:
            sys.exit(exit_code)


if __name__ == "__main__":
    main()

