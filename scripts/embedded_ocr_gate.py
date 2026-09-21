#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Embedded Open Code Review (OCR) Gate - Unified Quality Gate Runner
Orchestrates static safety, memory budget, struct alignment, call stack,
and complexity analyzers to enforce AI coding guardrails and legacy code suppression.
"""

import os
import sys
import json
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

script_dir = Path(__file__).resolve().parent
if str(script_dir) not in sys.path:
    sys.path.insert(0, str(script_dir))

from embedded_ocr_common import (
    resolve_changed_scope, is_file_or_line_touched,
    build_gate_verdict, format_ai_heal_instruction
)

# Import analyzer modules directly for in-process speed
import cppcheck_analyzer
import mem_budget_analyzer
import struct_analyzer
import stack_analyzer
import complexity_analyzer
import concurrency_analyzer
import polling_timeout_analyzer
import float_bloat_analyzer
import cmis_protocol_analyzer


def run_unified_ocr_gate(workspace_dir, changed_files=None, diff_ref=None, threshold_ccn=15, stack_size=8192, include_legacy=False):
    """
    Run the full suite of analyzers, filter by scope, and assemble unified gate report.
    """
    workspace = os.path.abspath(workspace_dir)
    scope = resolve_changed_scope(workspace, changed_files=changed_files, diff_ref=diff_ref, include_legacy=include_legacy)
    
    reports = {}
    all_heal_instructions = []
    
    # 1. Cppcheck Analyzer
    try:
        auto_cpp = cppcheck_analyzer.auto_discover_cppcheck_target(workspace)
        cpp_bin = cppcheck_analyzer.find_cppcheck_binary()
        cpp_res = cppcheck_analyzer.run_cppcheck(
            cpp_bin,
            project_path=auto_cpp["project"],
            src_dirs=auto_cpp["src_dirs"],
            scope=scope
        )
        reports["cppcheck"] = cpp_res
        all_heal_instructions.extend(cpp_res.get("ai_heal_instructions", []))
    except Exception as e:
        reports["cppcheck"] = {"error": f"Cppcheck scan failed: {str(e)}"}
        
    # 2. Stack Analyzer
    try:
        stack_res = stack_analyzer.auto_analyze_stack(workspace, reserved_stack_bytes=stack_size)
        stack_analyzer.evaluate_stack_gate(stack_res, scope)
        reports["stack"] = stack_res
        all_heal_instructions.extend(stack_res.get("ai_heal_instructions", []))
    except Exception as e:
        reports["stack"] = {"error": f"Stack analysis failed: {str(e)}"}
        
    # 3. Complexity Analyzer
    try:
        comp_res = complexity_analyzer.analyze_complexity(workspace, threshold=threshold_ccn)
        complexity_analyzer.evaluate_complexity_gate(comp_res, scope, threshold_ccn)
        reports["complexity"] = comp_res
        all_heal_instructions.extend(comp_res.get("ai_heal_instructions", []))
    except Exception as e:
        reports["complexity"] = {"error": f"Complexity analysis failed: {str(e)}"}
        
    # 4. Struct Padding Analyzer
    try:
        elf_file = struct_analyzer.auto_discover_elf(workspace)
        if elf_file:
            struct_res = struct_analyzer.analyze_struct_padding(elf_file)
            struct_analyzer.evaluate_struct_gate(struct_res, scope)
            reports["structs"] = struct_res
            all_heal_instructions.extend(struct_res.get("ai_heal_instructions", []))
        else:
            reports["structs"] = {"error": "ELF binary not found for struct DWARF analysis."}
    except Exception as e:
        reports["structs"] = {"error": f"Struct analysis failed: {str(e)}"}
        
    # 5. Memory Budget Analyzer
    try:
        auto_elf_map = mem_budget_analyzer.auto_discover_elf_map(workspace)
        mem_report = {
            "workspace": workspace,
            "elf_path": auto_elf_map["elf"],
            "map_path": auto_elf_map["map"]
        }
        if auto_elf_map["elf"]:
            mem_report["elf"] = mem_budget_analyzer.analyze_elf_binary(auto_elf_map["elf"])
        if auto_elf_map["map"]:
            mem_report["map"] = mem_budget_analyzer.analyze_map_contributions(auto_elf_map["map"])
        mem_budget_analyzer.evaluate_memory_gate(mem_report)
        reports["memory"] = mem_report
    except Exception as e:
        reports["memory"] = {"error": f"Memory budget analysis failed: {str(e)}"}
        
    # 6. Concurrency & ISR Race Analyzer
    try:
        concur_res = concurrency_analyzer.analyze_concurrency_hazards(workspace, scope=scope)
        reports["concurrency"] = concur_res
        all_heal_instructions.extend(concur_res.get("ai_heal_instructions", []))
    except Exception as e:
        reports["concurrency"] = {"error": f"Concurrency analysis failed: {str(e)}"}
        
    # 7. Hardware Polling Timeout Analyzer
    try:
        timeout_res = polling_timeout_analyzer.scan_workspace(workspace, scope, include_legacy)
        timeout_verdict = polling_timeout_analyzer.build_gate_verdict(
            new_blockers=timeout_res['new_blockers'],
            critical_issues=timeout_res['new_critical'],
            legacy_issues=timeout_res['legacy_suppressed'] if not include_legacy else timeout_res['legacy_included'],
            arch_hazards=[],
            scope=scope
        )
        timeout_heals = []
        for item in timeout_res['new_blockers'] + timeout_res['new_critical']:
            rel_f = os.path.relpath(item['file'], workspace).replace('\\', '/')
            timeout_heals.append({
                'rule_id': item['rule_id'],
                'file': rel_f,
                'full_path': item['file'].replace('\\', '/'),
                'line': item['line'],
                'message': item['message'],
                'action': item['action'],
                'instruction': f"Line {item['line']}: {item['suggested_fix']}"
            })
        reports["timeout"] = {
            "gate": timeout_verdict,
            "summary": timeout_res,
            "ai_heal_instructions": timeout_heals
        }
        all_heal_instructions.extend(timeout_heals)
    except Exception as e:
        reports["timeout"] = {"error": f"Polling timeout analysis failed: {str(e)}"}

    # 8. Soft-FPU & Float Bloat Analyzer
    try:
        float_res = float_bloat_analyzer.scan_workspace(workspace, scope, include_legacy)
        float_verdict = float_bloat_analyzer.build_gate_verdict(
            new_blockers=float_res['new_blockers'],
            critical_issues=float_res['new_critical'],
            legacy_issues=float_res['legacy_suppressed'] if not include_legacy else float_res['legacy_included'],
            arch_hazards=[],
            scope=scope
        )
        float_heals = []
        for item in float_res['new_blockers'] + float_res['new_critical']:
            rel_f = os.path.relpath(item['file'], workspace).replace('\\', '/')
            float_heals.append({
                'rule_id': item['rule_id'],
                'file': rel_f,
                'full_path': item['file'].replace('\\', '/'),
                'line': item['line'],
                'target': item.get('target', ''),
                'message': item['message'],
                'action': item['action'],
                'instruction': f"Line {item['line']}: {item['suggested_fix']}"
            })
        reports["float"] = {
            "gate": float_verdict,
            "summary": float_res,
            "ai_heal_instructions": float_heals
        }
        all_heal_instructions.extend(float_heals)
    except Exception as e:
        reports["float"] = {"error": f"Float bloat analysis failed: {str(e)}"}

    # 9. Optical Module CMIS Protocol Analyzer (Pluggable)
    # Active if cmis_project_profile.json exists or optical transceiver headers are found
    is_optical_project = (Path(workspace) / 'cmis_project_profile.json').exists() or any(
        (Path(workspace) / 'code' / '_BSP' / h).exists() for h in ['MSA_QDD.h', 'bsp_msa.h']
    )
    if is_optical_project:
        try:
            cmis_res = cmis_protocol_analyzer.scan_workspace(workspace, scope, include_legacy)
            cmis_verdict = cmis_protocol_analyzer.build_gate_verdict(
                new_blockers=cmis_res['new_blockers'],
                critical_issues=cmis_res['new_critical'],
                legacy_issues=cmis_res['legacy_suppressed'] if not include_legacy else cmis_res['legacy_included'],
                arch_hazards=[],
                scope=scope
            )
            cmis_heals = []
            for item in cmis_res['new_blockers'] + cmis_res['new_critical']:
                rel_f = os.path.relpath(item['file'], workspace).replace('\\', '/')
                cmis_heals.append({
                    'rule_id': item['rule_id'],
                    'file': rel_f,
                    'full_path': item['file'].replace('\\', '/'),
                    'line': item['line'],
                    'target': item.get('target', ''),
                    'message': item['message'],
                    'action': item['action'],
                    'pref_swap': item.get('pref_swap', 'SwapU16'),
                    'instruction': f"Line {item['line']}: {item['suggested_fix']}"
                })
            reports["cmis"] = {
                "gate": cmis_verdict,
                "summary": cmis_res,
                "ai_heal_instructions": cmis_heals
            }
            all_heal_instructions.extend(cmis_heals)
        except Exception as e:
            reports["cmis"] = {"error": f"CMIS protocol analysis failed: {str(e)}"}
        
    # Synthesize Unified Gate Verdict
    sub_verdicts = []
    total_blockers = 0
    total_legacy_suppressed = 0
    total_legacy_included = 0
    total_arch_hazards = 0
    
    for tool_name, rep in reports.items():
        gate = rep.get("gate", {})
        v = gate.get("verdict", "PASSED")
        sub_verdicts.append((tool_name, v, gate.get("exit_code", 0)))
        stats = gate.get("stats", {})
        total_blockers += stats.get("new_blockers", 0) + stats.get("new_critical", 0)
        total_legacy_suppressed += stats.get("legacy_suppressed", 0)
        total_legacy_included += stats.get("legacy_included", 0)
        total_arch_hazards += stats.get("arch_hazards", 0)
        
    # Highest severity exit code wins: 2 (Arch hazard) > 1 (Blocked) > 0 (Passed)
    exit_code = 0
    if total_arch_hazards > 0:
        verdict = "ARCHITECTURAL_HAZARD"
        exit_code = 2
        summary = f"Triggered {total_arch_hazards} global architectural hazard(s) in firmware memory/stack."
    elif total_blockers > 0:
        verdict = "BLOCKED"
        exit_code = 1
        summary = f"Blocked by {total_blockers} defect(s) in AI modified code. AI self-healing required."
    else:
        verdict = "PASSED"
        exit_code = 0
        if include_legacy:
            summary = f"Passed: Clean incremental changes (Included {total_legacy_included} legacy technical debt findings in report)."
        else:
            summary = f"Passed: Clean incremental changes (Automatically suppressed {total_legacy_suppressed} legacy technical debt findings)."
        
    unified_gate = {
        "verdict": verdict,
        "exit_code": exit_code,
        "is_incremental": scope.get("is_incremental", False),
        "include_legacy": include_legacy,
        "mode": scope.get("mode", "FULL_SCAN"),
        "touched_files": list(scope.get("touched_files", [])),
        "summary": summary,
        "stats": {
            "new_blockers": total_blockers,
            "arch_hazards": total_arch_hazards,
            "legacy_suppressed": total_legacy_suppressed,
            "legacy_included": total_legacy_included
        },
        "sub_gates": sub_verdicts
    }
    
    return {
        "gate": unified_gate,
        "reports": reports,
        "ai_heal_instructions": all_heal_instructions
    }


def format_gate_markdown(result):
    """Format unified Gate verdict and instructions into Markdown."""
    gate = result["gate"]
    verdict = gate["verdict"]
    include_legacy = gate.get("include_legacy", False)
    lines = []
    
    lines.append("# 🛡️ 嵌入式 AI 代码审查门禁总决断书 (Embedded OCR Gate)\n")
    
    if verdict == "BLOCKED":
        lines.append(f"> [!CAUTION]\n> **🚨 AI 增量代码质量门禁拦截 (BLOCKED)**\n> **{gate['summary']}**\n> AI 必须根据下方【自愈修复指令清单】修改代码后重新提交！\n")
    elif verdict == "ARCHITECTURAL_HAZARD":
        lines.append(f"> [!CAUTION]\n> **💥 老代码架构级性能警报 (ARCHITECTURAL_HAZARD)**\n> **{gate['summary']}**\n> 虽非当前修改直接引起，但系统内存/调用栈已濒临崩溃，需架构师决策！\n")
    else:
        lines.append(f"> [!NOTE]\n> **✅ 嵌入式 AI 质量门禁全绿通过 (PASSED)**\n> **{gate['summary']}**\n")
        
    lines.append("## 1. 门禁审计概览")
    lines.append(f"- **综合判定结果**: **`{verdict}`** (Exit Code: `{gate['exit_code']}`)")
    lines.append(f"- **审查作用域**: `{'🎯 增量审查模式' if gate['is_incremental'] else '🌐 全量全库扫描'}`")
    lines.append(f"- **老代码选项**: `{'📋 包含老代码历史问题 (--include-legacy)' if include_legacy else '🛡️ 排除并静默老代码 (默认)'}`")
    if gate.get("touched_files"):
        lines.append(f"- **本次审查触碰文件数**: `{len(gate['touched_files'])}` 个")
        for tf in gate["touched_files"][:5]:
            lines.append(f"  - `{tf}`")
    lines.append(f"- **🚨 新增阻断级缺陷 (Blockers)**: `{gate['stats']['new_blockers']}` 个")
    if include_legacy:
        lines.append(f"- **📜 老代码技术债务展示 (Legacy Included)**: `{gate['stats']['legacy_included']}` 个 (已汇总于下方)")
    else:
        lines.append(f"- **🛡️ 老代码技术债务静默 (Legacy Suppressed)**: `{gate['stats']['legacy_suppressed']}` 个 (零噪音干扰，添加 `--include-legacy` 可展开)")
    lines.append(f"- **💥 架构级碰撞隐患 (Arch Hazards)**: `{gate['stats']['arch_hazards']}` 个\n")
    
    lines.append("## 2. 嵌入式全域子系统质检清单 (8大通用门禁 + CMIS专属插件)")
    lines.append("| 质检维度 | 核心把关点 | 判定状态 | 备注 |")
    lines.append("| :--- | :--- | :--- | :--- |")
    tool_desc = {
        "cppcheck": "静态代码安全审计 (未初始化/空指针/越界)",
        "stack": "最大调用栈深与局部数组栈溢出防护",
        "complexity": "圈复杂度与大状态机认知负载",
        "structs": "结构体内存对齐与空洞率审计",
        "memory": "Flash/SRAM 物理内存预算与安全余量",
        "concurrency": "中断并发竞态与 volatile 强校验",
        "timeout": "硬件外设状态死等与防死锁超时校验",
        "float": "软浮点与 64 位双精度膨胀隐患审计",
        "cmis": "光模块 CMIS / MSA 协议安全规范 (大小端/时延)"
    }
    for name, v, code in gate.get("sub_gates", []):
        v_icon = "🟢 PASSED" if v == "PASSED" else ("🔴 BLOCKED" if v == "BLOCKED" else "🟡 ARCH_HAZARD")
        desc = tool_desc.get(name, "嵌入式系统安全把关")
        lines.append(f"| **`{name}`** | {desc} | **{v_icon}** | Code: {code} |")
        
    # AI Auto-Heal Instructions
    heals = result.get("ai_heal_instructions", [])
    if heals:
        lines.append("\n## 3. 🤖 AI 闭环自愈修复指令清单 (Actionable Auto-Heal Tasks)")
        lines.append("> [!IMPORTANT]\n> 以下修复指令已全部结构化输出至 JSON，大模型 Agent 可直接消费并执行修改：\n")
        for idx, h in enumerate(heals, 1):
            lines.append(f"### 任务 {idx}: `[{h['rule_id']}]` @ `{h['file']}:{h['line']}`")
            lines.append(f"- **动作类型**: `{h['action']}`")
            lines.append(f"- **问题说明**: {h['message']}")
            lines.append(f"- **自愈指令**: {h['instruction']}")
            if h.get("suggested_patch"):
                lines.append("```c")
                lines.append(h["suggested_patch"])
                lines.append("```")
            lines.append("")
            
    # Optional Section 4: Legacy Code Overview if included
    if include_legacy:
        lines.append("## 4. 📜 老代码历史技术债务全景清单 (Included Legacy Findings)")
        rep_cpp = result["reports"].get("cppcheck", {})
        rep_stack = result["reports"].get("stack", {})
        rep_comp = result["reports"].get("complexity", {})
        rep_struct = result["reports"].get("structs", {})
        
        lines.append(f"### 4.1 历史静态警告 (Cppcheck Legacy: {len(rep_cpp.get('legacy_suppressed', []))} 项)")
        for item in rep_cpp.get("legacy_suppressed", [])[:5]:
            fname = os.path.basename(item.get('file', ''))
            lines.append(f"- `[{item.get('id')}]` `{fname}:{item.get('line')}` - {item.get('message')}")
            
        lines.append(f"\n### 4.2 历史超大栈帧函数 (Stack Legacy: {len(rep_stack.get('legacy_suppressed_functions', []))} 个)")
        for f in rep_stack.get("legacy_suppressed_functions", [])[:5]:
            loc = f"{os.path.basename(f.get('file', ''))}:{f.get('line', '')}"
            lines.append(f"- `{f['name']}`: **`{f['stack_bytes']} B`** @ `{loc}`")
            
        lines.append(f"\n### 4.3 历史高圈复杂度函数 (Complexity Legacy: {len(rep_comp.get('legacy_suppressed_functions', []))} 个)")
        for f in rep_comp.get("legacy_suppressed_functions", [])[:5]:
            lines.append(f"- `{f['name']}`: CCN=**`{f['ccn']}`**, NLOC=`{f['nloc']}` @ `{f['file']}:{f['line']}`")
            
        lines.append(f"\n### 4.4 历史对齐空洞结构体 (Structs Legacy: {len(rep_struct.get('legacy_suppressed_structs', []))} 个)")
        for s in rep_struct.get("legacy_suppressed_structs", [])[:5]:
            lines.append(f"- `{s['name']}`: 空洞 `{s['hole_bytes']} B` ({s['waste_percentage']}%) @ `{s['decl_file']}`")
        lines.append("")
            
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Embedded Open Code Review (OCR) Unified Quality Gate")
    parser.add_argument("--workspace", "-w", default=".", help="Workspace root directory")
    parser.add_argument("--changed-files", nargs="*", help="Files modified by AI / current commit")
    parser.add_argument("--diff", nargs="?", const="HEAD", help="Use git diff to identify changed scope")
    parser.add_argument("--include-legacy", action="store_true", help="Include and report legacy technical debt (default: false, legacy code is suppressed)")
    parser.add_argument("--gate", action="store_true", default=True, help="Enforce quality gate exit code (default: True)")
    parser.add_argument("--no-gate", action="store_false", dest="gate", help="Do not exit with error code on blockers")
    parser.add_argument("--threshold", "-t", type=int, default=15, help="CCN threshold for warning (default: 15)")
    parser.add_argument("--stack-size", type=int, default=8192, help="Reserved stack size in bytes (default: 8192)")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Console output format")
    parser.add_argument("--output-dir", help="Directory to save reports (default: <workspace>/reports)")
    parser.add_argument("--no-save", action="store_true", help="Do not save reports to disk")
    
    args = parser.parse_args()
    workspace = os.path.abspath(args.workspace)
    
    result = run_unified_ocr_gate(
        workspace,
        changed_files=args.changed_files,
        diff_ref=args.diff,
        threshold_ccn=args.threshold,
        stack_size=args.stack_size,
        include_legacy=args.include_legacy
    )
    
    md_report = format_gate_markdown(result)
    reports_dir = args.output_dir or os.path.join(workspace, "reports")
    
    if not args.no_save:
        os.makedirs(reports_dir, exist_ok=True)
        md_file = os.path.join(reports_dir, "report_ocr_gate.md")
        json_file = os.path.join(reports_dir, "report_ocr_gate.json")
        with open(md_file, "w", encoding="utf-8") as f:
            f.write(md_report)
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        sys.stderr.write(f"\n[OCR Gate Generated]\n  ├─ Markdown (Human): {md_file}\n  └─ JSON (AI):        {json_file}\n\n")
        
    if args.format == "json":
        print(json.dumps(result["gate"], indent=2, ensure_ascii=False))
    else:
        print(md_report)
        
    # Exit with gate status
    if args.gate:
        sys.exit(result["gate"].get("exit_code", 0))


if __name__ == "__main__":
    main()

