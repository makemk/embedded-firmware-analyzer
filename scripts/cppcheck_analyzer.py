#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Embedded Cppcheck Static Analysis Tool
Runs cppcheck on embedded C/C++ projects, deduplicates warnings across translation units,
filters CMSIS/vendor register pointer comparison noise, and outputs structured reports.
"""

import os
import sys
import json
import argparse
import subprocess
import shutil
from pathlib import Path
import xml.etree.ElementTree as ET

# Ensure UTF-8 output on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass


def find_cppcheck_binary(custom_path=None):
    """Locate cppcheck binary on Windows/Linux."""
    if custom_path and os.path.isfile(custom_path):
        return custom_path
    
    # 1. On Windows: prioritize isolated bundled tool inside skill directory (zero host dependency)
    if sys.platform == 'win32':
        skill_root = Path(__file__).resolve().parent.parent
        bundled_cppcheck = skill_root / "tools" / "cppcheck" / "cppcheck.exe"
        if bundled_cppcheck.is_file():
            return str(bundled_cppcheck)
    
    # 2. Check system PATH (standard on Linux/macOS or if custom-installed on Windows)
    which_path = shutil.which("cppcheck")
    if which_path:
        return which_path
    
    # 3. Known default locations on Windows
    if sys.platform == 'win32':
        user_home = Path.home()
        candidates = [
            user_home / ".eide" / "tools" / "cppcheck" / "cppcheck.exe",
            Path(r"C:\Program Files\Cppcheck\cppcheck.exe"),
            Path(r"C:\Program Files (x86)\Cppcheck\cppcheck.exe"),
        ]
        for c in candidates:
            if c.is_file():
                return str(c)
    return None


def auto_discover_cppcheck_target(workspace_dir):
    """Auto-detect cppcheck project file or source directories."""
    workspace = Path(workspace_dir).resolve()
    cppcheck_projects = []
    
    for root, _, files in os.walk(workspace):
        if any(skip in root for skip in ['.git', 'node_modules', '.gemini']):
            continue
        for f in files:
            if f.endswith('.cppcheck'):
                cppcheck_projects.append(os.path.join(root, f))
                
    cppcheck_projects.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    best_proj = cppcheck_projects[0] if cppcheck_projects else None
    
    # Common embedded src dirs if no project file
    potential = ['src', 'code', 'Core', 'User', 'App', 'Drivers', 'bsp', 'CMSIS']
    src_dirs = [os.path.join(str(workspace), p) for p in potential if os.path.isdir(os.path.join(str(workspace), p))]
    if not src_dirs:
        src_dirs = [str(workspace)]
        
    return {
        "project": best_proj,
        "src_dirs": src_dirs
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


def run_cppcheck(cppcheck_bin, project_path=None, src_dirs=None, scope=None):
    """Run cppcheck with XML v2 output, parse findings, and filter by incremental scope."""
    if not cppcheck_bin or not os.path.isfile(cppcheck_bin):
        return {"error": "cppcheck executable not found."}
        
    cmd = [
        cppcheck_bin,
        "--xml",
        "--xml-version=2",
        "--enable=warning,style,portability",
        "--inconclusive",
        "--inline-suppr"
    ]
    
    # 2. Automatically bind embedded MCU 32-bit platform (eliminates desktop windows.cfg dependency and false positives)
    skill_root = Path(__file__).resolve().parent.parent
    arm_platform = skill_root / "tools" / "cppcheck" / "platforms" / "arm32-wchar_t4.xml"
    if arm_platform.is_file():
        cmd.append(f"--platform={arm_platform}")
    else:
        cmd.append("--platform=arm32-wchar_t4")
    
    if project_path and os.path.isfile(project_path):
        cmd.append(f"--project={project_path}")
    elif src_dirs:
        for s in src_dirs:
            if os.path.exists(s):
                cmd.append(s)
    else:
        return {"error": "No project file or source directory specified."}
        
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        xml_output = proc.stderr
    except Exception as e:
        return {"error": f"Failed to execute cppcheck: {str(e)}"}
        
    if not xml_output:
        return {
            "error": "Cppcheck produced empty output.",
            "raw": "No output"
        }
        
    # Robust XML slice: locate <?xml or <results to bypass any preceding warning/config text
    xml_start = xml_output.find('<?xml')
    if xml_start == -1:
        xml_start = xml_output.find('<results')
        
    if xml_start == -1:
        return {
            "error": "Cppcheck did not produce XML output.",
            "raw": xml_output[:1000] if xml_output else "No output"
        }
        
    clean_xml = xml_output[xml_start:]
    try:
        root = ET.fromstring(clean_xml)
    except ET.ParseError as e:
        return {"error": f"XML parse error: {str(e)}", "raw": clean_xml[:500]}
        
    critical_errors = []
    warnings = []
    portability = []
    style_issues = []
    legacy_suppressed = []
    ai_heal_instructions = []
    
    CRITICAL_IDS = {
        'uninitvar', 'nullPointer', 'nullPointerArithmetic', 'arrayIndexOutOfBounds',
        'bufferAccessOutOfBounds', 'zerodiv', 'memleak', 'resourceLeak',
        'uninitMemberVar', 'deallocuse', 'danglingTempVariable', 'objectIndex'
    }
    
    seen_findings = set()
    for err in root.findall('.//error'):
        err_id = err.attrib.get('id', '')
        severity = err.attrib.get('severity', '')
        msg = err.attrib.get('msg', '')
        verbose = err.attrib.get('verbose', '')
        cwe = err.attrib.get('cwe', '')
        
        locations = []
        for loc in err.findall('location'):
            locations.append({
                "file": loc.attrib.get('file', ''),
                "line": int(loc.attrib.get('line', 0)),
                "column": int(loc.attrib.get('column', 0)),
                "info": loc.attrib.get('info', '')
            })
            
        primary_loc = locations[0] if locations else {"file": "", "line": 0, "column": 0, "info": ""}
        fpath = primary_loc["file"].replace('\\', '/')
        line_no = primary_loc["line"]
        
        # Deduplicate identical findings across translation units
        dedup_key = (err_id, fpath, line_no)
        if dedup_key in seen_findings:
            continue
        seen_findings.add(dedup_key)
        
        # Filter benign vendor/CMSIS assembly comparison pointer warnings
        is_vendor_header = any(v in fpath.lower() for v in ['cmsis_gcc.h', 'cmsis_armcc.h', 'core_cm', 'cmsis_iccarm.h'])
        if is_vendor_header and err_id == 'comparePointers':
            continue
            
        entry = {
            "id": err_id,
            "severity": severity,
            "message": msg,
            "verbose": verbose,
            "cwe": cwe,
            "file": primary_loc["file"],
            "line": line_no,
            "locations": locations
        }
        
        # Incremental Scope Filtering: Check if this finding falls inside touched files/lines
        is_touched = True
        if scope and scope.get("is_incremental"):
            is_touched = is_file_or_line_touched(fpath, line_no, scope)
            
        if not is_touched:
            legacy_suppressed.append(entry)
            continue
            
        # Touched new finding
        is_crit = err_id in CRITICAL_IDS or severity == 'error'
        if is_crit:
            critical_errors.append(entry)
            # Generate AI auto-heal prompt
            if err_id == 'uninitvar':
                action = "INITIALIZE_VARIABLE"
                instr = f"Variable '{msg.split()[-1]}' is read without initialization. Explicitly initialize it at declaration (e.g. 'int val = 0;')."
            elif err_id in ['nullPointer', 'nullPointerArithmetic']:
                action = "ADD_NULL_CHECK"
                instr = f"Potential null pointer dereference: {msg}. Add an explicit null guard before accessing pointer."
            elif err_id in ['arrayIndexOutOfBounds', 'bufferAccessOutOfBounds']:
                action = "CHECK_BUFFER_BOUNDS"
                instr = f"Buffer overflow risk: {msg}. Add boundary validation or clamp index variable."
            elif err_id == 'objectIndex':
                action = "FIX_SCALAR_INDEXING"
                instr = f"Scalar variable accessed as array: {msg}. Check pointer arithmetic or array definition."
            else:
                action = "FIX_CRITICAL_DEFECT"
                instr = f"Resolve critical defect [{err_id}]: {msg}"
            ai_heal_instructions.append(format_ai_heal_instruction(err_id, fpath, line_no, msg, action, instr))
        elif severity == 'portability':
            portability.append(entry)
            if err_id == 'invalidPointerCast':
                ai_heal_instructions.append(format_ai_heal_instruction(
                    err_id, fpath, line_no, msg, "FIX_STRICT_ALIASING",
                    "Pointer cast violates strict aliasing or alignment. Use memcpy or an explicit union for data reinterpretation."
                ))
        elif severity == 'warning':
            warnings.append(entry)
        else:
            style_issues.append(entry)
            
    scope_dict = scope or {"is_incremental": False}
    gate_verdict = build_gate_verdict(critical_errors, portability, legacy_suppressed, [], scope_dict)
    
    return {
        "gate": gate_verdict,
        "summary": {
            "critical_count": len(critical_errors),
            "warning_count": len(warnings),
            "portability_count": len(portability),
            "style_count": len(style_issues),
            "legacy_suppressed_count": len(legacy_suppressed),
            "total_new_findings": len(critical_errors) + len(warnings) + len(portability) + len(style_issues)
        },
        "critical_issues": critical_errors,
        "portability_issues": portability,
        "warnings": warnings,
        "style_issues": style_issues[:30],
        "legacy_suppressed": legacy_suppressed[:50],
        "ai_heal_instructions": ai_heal_instructions
    }


def format_markdown_report(result):
    """Format static analysis findings into clean Markdown."""
    lines = []
    lines.append("# 嵌入式 C/C++ 静态代码安全分析报告 (Cppcheck Engine)\n")
    
    if "error" in result:
        lines.append(f"> [!WARNING]\n> {result['error']}")
        return "\n".join(lines)
        
    gate = result.get("gate", {})
    verdict = gate.get("verdict", "PASSED")
    if verdict == "BLOCKED":
        lines.append(f"> [!CAUTION]\n> **🚨 嵌入式 AI 质量门禁拦截 (BLOCKED)**: {gate.get('summary', '')}\n")
    else:
        lines.append(f"> [!NOTE]\n> **✅ 嵌入式 AI 质量门禁通过 (PASSED)**: {gate.get('summary', '')}\n")
        
    summ = result["summary"]
    lines.append("## 1. 缺陷检测统计全景")
    lines.append(f"- **门禁判定结果**: **`{verdict}`** (Exit code: `{gate.get('exit_code', 0)}`)")
    lines.append(f"- **增量审查模式**: `{'已启用 (仅扫描触碰变更)' if gate.get('is_incremental') else '全量扫描'}`")
    lines.append(f"- **🚨 本次新增致命缺陷**: `{summ['critical_count']}` 个")
    lines.append(f"- **⚠️ 本次新增可移植性问题**: `{summ['portability_count']}` 个")
    lines.append(f"- **ℹ️ 本次新增常规警告/风格**: `{summ['warning_count'] + summ['style_count']}` 个")
    lines.append(f"- **🛡️ 老代码历史技术债务静默**: `{summ['legacy_suppressed_count']}` 个 (已安全跳过)\n")
    
    # Critical findings
    if summ['critical_count'] > 0:
        lines.append("## 2. 🚨 致命缺陷列表 (必须由 AI 立即自我修复)")
        lines.append("> [!CAUTION]\n> 以下缺陷存在于本次新增/修改的代码中，量产直接引发死机或不可预测行为！\n")
        lines.append("| 序号 | 缺陷类型 (ID) | 所在文件与行号 | 详细说明 | 修复建议 |")
        lines.append("| :---: | :--- | :--- | :--- | :--- |")
        for idx, item in enumerate(result["critical_issues"], 1):
            fname = os.path.basename(item['file']) if item['file'] else "Unknown"
            loc = f"`{fname}:{item['line']}`"
            lines.append(f"| {idx} | **`[{item['id']}]`** | {loc} | {item['message']} | 显式初始化/判空保护 |")
            
        if result.get("ai_heal_instructions"):
            lines.append("\n### 🤖 AI 自愈修复指令清单 (Auto-Heal Instructions):")
            for h in result["ai_heal_instructions"]:
                lines.append(f"- **`{h['file']}:{h['line']}`** [{h['rule_id']}]: {h['instruction']}")
    else:
        lines.append("## 2. 致命缺陷检查")
        lines.append("> [!NOTE]\n> ✅ 本次改动未发现新增未初始化变量、空指针、数组越界等致命缺陷。\n")
        
    # Portability
    if summ['portability_count'] > 0:
        lines.append("\n## 3. ⚠️ 嵌入式可移植性与指针别名隐患")
        lines.append("| 序号 | 问题类型 | 文件行号 | 说明 |")
        lines.append("| :---: | :--- | :--- | :--- |")
        for idx, item in enumerate(result["portability_issues"][:15], 1):
            fname = os.path.basename(item['file']) if item['file'] else "Unknown"
            lines.append(f"| {idx} | `[{item['id']}]` | `{fname}:{item['line']}` | {item['message']} |")
            
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
    parser = argparse.ArgumentParser(description="Embedded Cppcheck Static Analysis Tool")
    parser.add_argument("--workspace", "-w", default=".", help="Workspace root directory")
    parser.add_argument("--project", "-p", help="Path to .cppcheck project file")
    parser.add_argument("--src", nargs="*", help="Source directories to scan")
    parser.add_argument("--cppcheck-bin", help="Path to cppcheck executable")
    parser.add_argument("--changed-files", nargs="*", help="Files modified by AI/current commit")
    parser.add_argument("--diff", nargs="?", const="HEAD", help="Use git diff to identify changed scope")
    parser.add_argument("--include-legacy", action="store_true", help="Include legacy technical debt in reports")
    parser.add_argument("--gate", action="store_true", help="Enforce quality gate exit code (1 on blockers)")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Console output format")
    parser.add_argument("--output-dir", help="Directory to save reports (default: <workspace>/reports)")
    parser.add_argument("--output", "-o", help="Custom output path or prefix")
    parser.add_argument("--no-save", action="store_true", help="Do not save reports to disk")
    
    args = parser.parse_args()
    workspace = os.path.abspath(args.workspace)
    
    # Resolve incremental scope
    scope = resolve_changed_scope(workspace, changed_files=args.changed_files, diff_ref=args.diff, include_legacy=args.include_legacy)
    
    auto = auto_discover_cppcheck_target(workspace)
    proj = args.project or auto["project"]
    srcs = args.src or auto["src_dirs"]
    cppcheck_bin = find_cppcheck_binary(args.cppcheck_bin)
    
    res = run_cppcheck(cppcheck_bin, proj, srcs, scope=scope)
    
    md_report = format_markdown_report(res)
    reports_dir = args.output_dir or os.path.join(workspace, "reports")
    save_dual_reports(reports_dir, "report_cppcheck", md_report, res, args.output, args.no_save)
    
    if args.format == "json":
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        print(md_report)
        
    # Enforce gate exit code
    if args.gate and "gate" in res:
        exit_code = res["gate"].get("exit_code", 0)
        if exit_code != 0:
            sys.exit(exit_code)


if __name__ == "__main__":
    main()

