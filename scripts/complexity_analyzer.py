#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Embedded Code Complexity & Cognitive Load Analyzer (Lizard Engine)
Measures McCabe Cyclomatic Complexity (CCN), NLOC, parameter counts,
and flags high-risk state machines and bug shelter functions.
"""

import os
import sys
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

try:
    import lizard
except ImportError:
    lizard = None


def auto_discover_source_dirs(workspace_dir):
    """Find directories containing C/C++ source code."""
    workspace = Path(workspace_dir).resolve()
    potential = ['code', 'src', 'Source', 'Core', 'User', 'App', 'Drivers', '_BSP', '_HAL_MCU', '_HAL_DSP']
    found_dirs = []
    
    for p in potential:
        d = workspace / p
        if d.is_dir():
            found_dirs.append(str(d))
            
    if not found_dirs:
        found_dirs = [str(workspace)]
        
    return found_dirs


def analyze_complexity(workspace_dir, scan_dirs=None, threshold=15, query_func=None):
    """Run lizard analysis across all C/C++ files in the workspace."""
    if not lizard:
        return {
            "error": "lizard library is not installed.",
            "hint": "Run 'pip install lizard' to enable complexity analysis."
        }
        
    workspace = Path(workspace_dir).resolve()
    if not scan_dirs:
        scan_dirs = auto_discover_source_dirs(workspace_dir)
        
    all_files = []
    for s_dir in scan_dirs:
        for root, _, files in os.walk(s_dir):
            if any(skip in root for skip in ['.git', 'build', 'node_modules', '.gemini', 'CMSIS']):
                continue
            for f in files:
                if f.endswith(('.c', '.h', '.cpp', '.hpp')):
                    all_files.append(os.path.join(root, f))
                    
    total_nloc = 0
    total_funcs = 0
    all_functions = []
    file_summaries = {}
    
    for fpath in all_files:
        try:
            res = lizard.analyze_file(fpath)
            total_nloc += res.nloc
            rel_path = os.path.relpath(fpath, workspace_dir).replace('\\', '/')
            
            file_funcs = []
            for fn in res.function_list:
                total_funcs += 1
                ccn = fn.cyclomatic_complexity
                nloc = fn.nloc
                tokens = fn.token_count
                params = len(fn.parameters)
                
                # Risk Classification
                if ccn <= 10:
                    risk = "LOW"
                    rating = "🟢 优秀"
                elif ccn <= 15:
                    risk = "MODERATE"
                    rating = "🟡 中等"
                elif ccn <= 25:
                    risk = "HIGH"
                    rating = "🟠 高危"
                else:
                    risk = "CRITICAL"
                    rating = "🔴 极高危 (Bug 庇护所)"
                    
                entry = {
                    "name": fn.name,
                    "file": rel_path,
                    "line": fn.start_line,
                    "end_line": fn.end_line,
                    "ccn": ccn,
                    "nloc": nloc,
                    "tokens": tokens,
                    "parameters_count": params,
                    "parameters": fn.parameters,
                    "risk_level": risk,
                    "rating": rating
                }
                all_functions.append(entry)
                file_funcs.append(entry)
                
            file_summaries[rel_path] = {
                "nloc": res.nloc,
                "function_count": len(file_funcs),
                "avg_ccn": round(sum(f["ccn"] for f in file_funcs) / len(file_funcs), 1) if file_funcs else 0,
                "max_ccn": max((f["ccn"] for f in file_funcs), default=0)
            }
        except Exception:
            pass
            
    all_functions.sort(key=lambda x: x["ccn"], reverse=True)
    
    # Check for specific query
    if query_func:
        matched = [f for f in all_functions if f["name"].lower() == query_func.lower()]
        if matched:
            return {"queried_function": matched[0], "all_count": len(all_functions)}
        return {"error": f"Function '{query_func}' not found in analyzed source files."}
        
    # Stats
    critical_funcs = [f for f in all_functions if f["ccn"] > 25]
    high_funcs = [f for f in all_functions if 15 < f["ccn"] <= 25]
    moderate_funcs = [f for f in all_functions if 10 < f["ccn"] <= 15]
    safe_funcs = [f for f in all_functions if f["ccn"] <= 10]
    
    # Overly long functions (NLOC >= 100)
    monolithic_funcs = sorted([f for f in all_functions if f["nloc"] >= 100], key=lambda x: x["nloc"], reverse=True)
    
    # Top files by complexity
    top_complex_files = sorted(
        [{"file": k, **v} for k, v in file_summaries.items()],
        key=lambda x: x["max_ccn"],
        reverse=True
    )[:10]
    
    avg_ccn = round(sum(f["ccn"] for f in all_functions) / len(all_functions), 2) if all_functions else 0
    
    return {
        "summary": {
            "total_files_analyzed": len(all_files),
            "total_nloc": total_nloc,
            "total_functions": total_funcs,
            "average_ccn": avg_ccn,
            "critical_count": len(critical_funcs),
            "high_risk_count": len(high_funcs),
            "moderate_count": len(moderate_funcs),
            "safe_count": len(safe_funcs),
            "monolithic_funcs_count": len(monolithic_funcs)
        },
        "top_complex_functions": all_functions[:15],
        "top_monolithic_functions": monolithic_funcs[:10],
        "top_complex_files": top_complex_files
    }


try:
    from embedded_ocr_common import (
        resolve_changed_scope, is_file_or_line_touched,
        build_gate_verdict, format_ai_heal_instruction
    )
except ImportError:
    script_dir = Path(__file__).resolve().parent
    sys.path.insert(0, str(script_dir))
    from embedded_ocr_common import (
        resolve_changed_scope, is_file_or_line_touched,
        build_gate_verdict, format_ai_heal_instruction
    )


def evaluate_complexity_gate(result, scope, threshold=15):
    """Evaluate complexity gate verdict against touched scope."""
    if "error" in result or "summary" not in result:
        return
        
    top_complex = result.get("top_complex_functions", [])
    new_blockers = []
    legacy_suppressed = []
    ai_heal_instructions = []
    
    for f in top_complex:
        is_touched = is_file_or_line_touched(f.get("file"), f.get("line"), scope)
        if is_touched:
            if f.get("ccn", 0) > threshold:
                new_blockers.append(f)
                ai_heal_instructions.append(format_ai_heal_instruction(
                    "HIGH_CYCLOMATIC_COMPLEXITY",
                    f.get("file"),
                    f.get("line"),
                    f"Function '{f['name']}' CCN={f['ccn']} exceeds threshold ({threshold}).",
                    "REFACTOR_STATE_MACHINE_OR_TABLE",
                    f"Function '{f['name']}' has high cyclomatic complexity (CCN={f['ccn']}). Replace deep nested if-else/switch with table-driven dispatch, guard clauses, or sub-function extraction."
                ))
        else:
            if f.get("ccn", 0) > threshold:
                legacy_suppressed.append(f)
                
    gate = build_gate_verdict(new_blockers, [], legacy_suppressed, [], scope)
    result["gate"] = gate
    result["new_complex_functions"] = new_blockers
    result["legacy_suppressed_functions"] = legacy_suppressed
    result["ai_heal_instructions"] = ai_heal_instructions


def format_markdown_report(result):
    """Format complexity findings into clean Markdown report."""
    lines = []
    lines.append("# 嵌入式固件代码圈复杂度与认知负载深度报告 (Lizard Engine)\n")
    
    if "error" in result:
        lines.append(f"> [!WARNING]\n> {result['error']}")
        if "hint" in result:
            lines.append(f"> *建议*: {result['hint']}")
        return "\n".join(lines)
        
    gate = result.get("gate", {})
    verdict = gate.get("verdict", "PASSED")
    if verdict == "BLOCKED":
        lines.append(f"> [!CAUTION]\n> **🚨 嵌入式 AI 复杂度门禁拦截 (BLOCKED)**: {gate.get('summary', '')}\n")
    else:
        lines.append(f"> [!NOTE]\n> **✅ 嵌入式 AI 复杂度门禁通过 (PASSED)**: {gate.get('summary', '')}\n")
        
    summ = result["summary"]
    lines.append("## 1. 代码质量与复杂度全景总览")
    lines.append(f"- **门禁判定结果**: **`{verdict}`** (Exit code: `{gate.get('exit_code', 0)}`)")
    lines.append(f"- **扫描源码文件数**: `{summ['total_files_analyzed']}` 个 (有效代码行 NLOC: `{summ['total_nloc']:,}` 行)")
    lines.append(f"- **分析函数总数**: `{summ['total_functions']}` 个 (全局平均圈复杂度: **`{summ['average_ccn']}`**)")
    if gate.get("is_incremental"):
        lines.append(f"- **🛡️ 老代码历史高复杂度函数静默**: `{len(result.get('legacy_suppressed_functions', []))}` 个 (已跳过不阻断)")
    lines.append(f"- **复杂度分布**:")
    lines.append(f"  - 🟢 **健康正常 (CCN <= 10)**: `{summ['safe_count']}` 个 ({summ['safe_count']/summ['total_functions']*100:.1f}%)")
    lines.append(f"  - 🟡 **中等警戒 (11 <= CCN <= 15)**: `{summ['moderate_count']}` 个")
    lines.append(f"  - 🟠 **高危复杂 (16 <= CCN <= 25)**: `{summ['high_risk_count']}` 个")
    lines.append(f"  - 🔴 **极高危/Bug庇护所 (CCN > 25)**: **`{summ['critical_count']}`** 个\n")
    
    # Top complex in touched scope
    new_complex = result.get("new_complex_functions", [])
    if new_complex:
        lines.append("## 2. 🔴 本次修改新增高复杂度函数 (AI 需重点重构)")
        lines.append("| 序号 | 函数名称 | 圈复杂度 (CCN) | 代码行 (NLOC) | 危险评级 | 所在源文件位置 |")
        lines.append("| :---: | :--- | :--- | :--- | :--- | :--- |")
        for idx, f in enumerate(new_complex, 1):
            loc = f"`{f['file']}:{f['line']}`"
            lines.append(f"| {idx} | **`{f['name']}`** | **`{f['ccn']}`** | {f['nloc']} 行 | {f['rating']} | {loc} |")
            
        if result.get("ai_heal_instructions"):
            lines.append("\n### 🤖 AI 自愈修复指令清单:")
            for h in result["ai_heal_instructions"]:
                lines.append(f"- **`{h['file']}:{h['line']}`** [{h['action']}]: {h['instruction']}")
    else:
        lines.append("## 2. 新增高复杂度函数检查")
        lines.append("> [!NOTE]\n> ✅ 本次改动未引入 CCN > 15 的高危复杂函数。\n")
        
    return "\n".join(lines)


def save_dual_reports(output_dir, base_name, md_content, json_data, custom_output=None, no_save=False):
    """
    Save both human-readable Markdown (.md) and machine-readable JSON (.json) reports.
    """
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
    parser = argparse.ArgumentParser(description="Embedded Code Complexity & Cognitive Load Analyzer")
    parser.add_argument("--workspace", "-w", default=".", help="Workspace root directory")
    parser.add_argument("--threshold", "-t", type=int, default=15, help="CCN threshold for warning (default: 15)")
    parser.add_argument("--query-func", "-q", help="Deep dive into a specific function name")
    parser.add_argument("--src", nargs="*", help="Specific source directories to analyze")
    parser.add_argument("--changed-files", nargs="*", help="Files modified by AI/current commit")
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
    
    res = analyze_complexity(workspace, args.src, args.threshold, args.query_func)
    evaluate_complexity_gate(res, scope, args.threshold)
    
    md_report = format_markdown_report(res)
    reports_dir = args.output_dir or os.path.join(workspace, "reports")
    save_dual_reports(reports_dir, "report_complexity", md_report, res, args.output, args.no_save)
    
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

