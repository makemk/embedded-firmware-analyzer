#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Embedded Struct Padding & Alignment Analyzer (Python DWARF Engine)
Extracts C struct layouts from ELF DWARF debug information, calculates padding holes,
classifies hardware vs application structs, and simulates optimal member reordering.
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
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile = None


def resolve_type_info(die, dwarf_info=None):
    """Recursively resolve DWARF type to find byte size, alignment, and readable name."""
    if not die:
        return {"name": "void", "size": 0, "align": 1}
        
    tag = die.tag
    attrs = die.attributes
    
    # Base type
    if tag == 'DW_TAG_base_type':
        name = attrs['DW_AT_name'].value.decode('utf-8', errors='ignore') if 'DW_AT_name' in attrs else 'unknown'
        sz = attrs['DW_AT_byte_size'].value if 'DW_AT_byte_size' in attrs else 1
        align = sz if sz in [1, 2, 4, 8] else 4
        return {"name": name, "size": sz, "align": min(align, 4)}
        
    # Pointer type
    elif tag == 'DW_TAG_pointer_type':
        sz = attrs['DW_AT_byte_size'].value if 'DW_AT_byte_size' in attrs else 4
        return {"name": "pointer", "size": sz, "align": sz}
        
    # Typedef
    elif tag == 'DW_TAG_typedef':
        name = attrs['DW_AT_name'].value.decode('utf-8', errors='ignore') if 'DW_AT_name' in attrs else 'typedef'
        if 'DW_AT_type' in attrs:
            target = die.get_DIE_from_attribute('DW_AT_type')
            info = resolve_type_info(target, dwarf_info)
            return {"name": name, "size": info["size"], "align": info["align"], "base_name": info["name"]}
        return {"name": name, "size": 4, "align": 4}
        
    # Const / Volatile
    elif tag in ['DW_TAG_const_type', 'DW_TAG_volatile_type']:
        if 'DW_AT_type' in attrs:
            target = die.get_DIE_from_attribute('DW_AT_type')
            return resolve_type_info(target, dwarf_info)
        return {"name": "void", "size": 0, "align": 1}
        
    # Array type
    elif tag == 'DW_TAG_array_type':
        elem_info = {"name": "elem", "size": 1, "align": 1}
        if 'DW_AT_type' in attrs:
            elem_info = resolve_type_info(die.get_DIE_from_attribute('DW_AT_type'), dwarf_info)
            
        dims = []
        for child in die.iter_children():
            if child.tag == 'DW_TAG_subrange_type':
                if 'DW_AT_upper_bound' in child.attributes:
                    dims.append(child.attributes['DW_AT_upper_bound'].value + 1)
                elif 'DW_AT_count' in child.attributes:
                    dims.append(child.attributes['DW_AT_count'].value)
                    
        total_elements = 1
        dim_str = ""
        for d in dims:
            total_elements *= d
            dim_str += f"[{d}]"
            
        total_sz = elem_info["size"] * total_elements
        return {
            "name": f"{elem_info['name']}{dim_str}",
            "size": total_sz,
            "align": elem_info["align"],
            "element_count": total_elements
        }
        
    # Struct or Union type
    elif tag in ['DW_TAG_structure_type', 'DW_TAG_union_type']:
        name = attrs['DW_AT_name'].value.decode('utf-8', errors='ignore') if 'DW_AT_name' in attrs else 'struct'
        sz = attrs['DW_AT_byte_size'].value if 'DW_AT_byte_size' in attrs else 0
        return {"name": name, "size": sz, "align": 4}
        
    # Enumeration
    elif tag == 'DW_TAG_enumeration_type':
        name = attrs['DW_AT_name'].value.decode('utf-8', errors='ignore') if 'DW_AT_name' in attrs else 'enum'
        sz = attrs['DW_AT_byte_size'].value if 'DW_AT_byte_size' in attrs else 4
        return {"name": name, "size": sz, "align": sz}
        
    # Fallback
    sz = attrs['DW_AT_byte_size'].value if 'DW_AT_byte_size' in attrs else 0
    return {"name": "other", "size": sz, "align": 4 if sz >= 4 else (2 if sz == 2 else 1)}


def simulate_optimal_layout(members):
    """
    Simulate greedy optimal member layout (sorting members by alignment requirement descending).
    In 32-bit ARM, sorting 4-byte aligned members first, then 2-byte, then 1-byte eliminates all internal holes.
    """
    if not members:
        return {"repacked_size": 0, "savings": 0, "order": []}
        
    # Separate members with valid sizes
    valid_members = [m for m in members if m["size"] > 0]
    
    # Sort members: align descending (4, 2, 1), then size descending
    sorted_members = sorted(valid_members, key=lambda m: (m.get("align", 1), m["size"]), reverse=True)
    
    current_offset = 0
    max_align = 1
    new_layout = []
    
    for m in sorted_members:
        align = m.get("align", 1)
        if align > max_align:
            max_align = align
            
        # Align current offset
        if current_offset % align != 0:
            current_offset += (align - (current_offset % align))
            
        new_layout.append({
            "name": m["name"],
            "type": m.get("type_name", ""),
            "offset": current_offset,
            "size": m["size"]
        })
        current_offset += m["size"]
        
    # Pad to max alignment (standard C struct rule)
    if max_align > 1 and (current_offset % max_align != 0):
        current_offset += (max_align - (current_offset % max_align))
        
    return {
        "repacked_size": current_offset,
        "new_layout": new_layout,
        "max_align": max_align
    }


def analyze_struct_padding(elf_path, query_struct=None):
    """Analyze all struct layouts in the ELF file using DWARF debug info."""
    if not ELFFile:
        return {"error": "pyelftools is not installed."}
        
    if not os.path.isfile(elf_path):
        return {"error": f"ELF file not found: {elf_path}"}
        
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            return {
                "error": "ELF binary has no DWARF debug information.",
                "hint": "Compile with '-g' or '--debug' in GCC / Keil to enable struct layout auditing."
            }
            
        dwarf = elf.get_dwarf_info()
        
        # 1. Map DIE offset -> typedef name
        typedef_map = {}
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag == 'DW_TAG_typedef':
                    tname = die.attributes['DW_AT_name'].value.decode('utf-8', errors='ignore') if 'DW_AT_name' in die.attributes else ''
                    if 'DW_AT_type' in die.attributes:
                        target = die.get_DIE_from_attribute('DW_AT_type')
                        if target:
                            typedef_map[target.offset] = tname
                            
        # 2. Iterate Struct DIEs
        analyzed_structs = []
        seen_names = set()
        
        for cu in dwarf.iter_CUs():
            # Extract CU line table file list for source file location
            lineprog = dwarf.line_program_for_CU(cu)
            file_entries = lineprog['file_entry'] if lineprog else []
            
            for die in cu.iter_DIEs():
                if die.tag == 'DW_TAG_structure_type':
                    name = None
                    if 'DW_AT_name' in die.attributes:
                        name = die.attributes['DW_AT_name'].value.decode('utf-8', errors='ignore')
                    elif die.offset in typedef_map:
                        name = typedef_map[die.offset]
                        
                    if not name or name in seen_names:
                        continue
                    seen_names.add(name)
                    
                    st_sz = die.attributes['DW_AT_byte_size'].value if 'DW_AT_byte_size' in die.attributes else 0
                    if st_sz == 0:
                        continue
                        
                    # Decl location
                    decl_file = "Unknown"
                    decl_line = 0
                    if 'DW_AT_decl_file' in die.attributes:
                        f_idx = die.attributes['DW_AT_decl_file'].value - 1
                        if 0 <= f_idx < len(file_entries):
                            decl_file = file_entries[f_idx].name.decode('utf-8', errors='ignore')
                    if 'DW_AT_decl_line' in die.attributes:
                        decl_line = die.attributes['DW_AT_decl_line'].value
                        
                    members = []
                    for child in die.iter_children():
                        if child.tag == 'DW_TAG_member':
                            m_name = child.attributes['DW_AT_name'].value.decode('utf-8', errors='ignore') if 'DW_AT_name' in child.attributes else '<anonymous>'
                            
                            # Location
                            m_offset = 0
                            if 'DW_AT_data_member_location' in child.attributes:
                                m_offset = child.attributes['DW_AT_data_member_location'].value
                                
                            # Type & Size
                            t_info = {"name": "unknown", "size": 0, "align": 1}
                            if 'DW_AT_type' in child.attributes:
                                t_info = resolve_type_info(child.get_DIE_from_attribute('DW_AT_type'), dwarf)
                                
                            m_size = child.attributes['DW_AT_byte_size'].value if 'DW_AT_byte_size' in child.attributes else t_info["size"]
                            
                            members.append({
                                "name": m_name,
                                "type_name": t_info["name"],
                                "offset": m_offset,
                                "size": m_size,
                                "align": t_info["align"]
                            })
                            
                    if not members:
                        continue
                        
                    members.sort(key=lambda x: x['offset'])
                    
                    # Compute holes
                    holes = []
                    total_hole_bytes = 0
                    for i in range(len(members) - 1):
                        expected_next = members[i]['offset'] + members[i]['size']
                        actual_next = members[i+1]['offset']
                        if actual_next > expected_next and members[i]['size'] > 0:
                            h_size = actual_next - expected_next
                            holes.append({
                                "after_member": members[i]['name'],
                                "offset": expected_next,
                                "hole_size": h_size,
                                "is_tail": False
                            })
                            total_hole_bytes += h_size
                            
                    # Tail padding
                    if members:
                        last_m = members[-1]
                        last_end = last_m['offset'] + last_m['size']
                        if st_sz > last_end and last_m['size'] > 0:
                            tail_pad = st_sz - last_end
                            holes.append({
                                "after_member": f"{last_m['name']} (Tail Padding)",
                                "offset": last_end,
                                "hole_size": tail_pad,
                                "is_tail": True
                            })
                            total_hole_bytes += tail_pad
                            
                    # Classify category
                    is_hw_reg = any(k in name for k in ['_TypeDef', 'NVIC', 'SCB', 'CoreDebug', 'SysTick']) or 'adi_' in decl_file.lower() or 'aducm' in decl_file.lower()
                    category = "Hardware Peripheral Register" if is_hw_reg else "Application / Firmware Business Struct"
                    
                    # Simulation
                    repack = simulate_optimal_layout(members)
                    savings = max(0, st_sz - repack["repacked_size"])
                    
                    st_entry = {
                        "name": name,
                        "category": category,
                        "decl_file": decl_file,
                        "decl_line": decl_line,
                        "total_size": st_sz,
                        "hole_bytes": total_hole_bytes,
                        "waste_percentage": round((total_hole_bytes / st_sz) * 100, 1) if st_sz > 0 else 0,
                        "members_count": len(members),
                        "members": members,
                        "holes": holes,
                        "repack_simulation": {
                            "repacked_size": repack["repacked_size"],
                            "bytes_saved": savings,
                            "optimized_percentage": round((savings / st_sz) * 100, 1) if st_sz > 0 else 0,
                            "new_layout": repack["new_layout"]
                        }
                    }
                    analyzed_structs.append(st_entry)
                    
        # Filter if queried
        if query_struct:
            matched = [s for s in analyzed_structs if s["name"].lower() == query_struct.lower()]
            if matched:
                return {"queried_struct": matched[0], "all_count": len(analyzed_structs)}
            return {"error": f"Struct '{query_struct}' not found in DWARF debug symbols."}
            
        # Sort by wasted hole bytes
        app_structs = [s for s in analyzed_structs if s["category"] != "Hardware Peripheral Register"]
        hw_structs = [s for s in analyzed_structs if s["category"] == "Hardware Peripheral Register"]
        
        app_structs.sort(key=lambda x: x["hole_bytes"], reverse=True)
        hw_structs.sort(key=lambda x: x["hole_bytes"], reverse=True)
        
        return {
            "summary": {
                "total_structs_analyzed": len(analyzed_structs),
                "app_structs_count": len(app_structs),
                "hw_structs_count": len(hw_structs),
                "app_structs_with_holes": len([s for s in app_structs if s["hole_bytes"] > 0]),
                "total_app_wasted_bytes": sum(s["hole_bytes"] for s in app_structs)
            },
            "top_wasteful_app_structs": app_structs[:15],
            "hardware_register_structs": hw_structs[:10]
        }


def format_markdown_report(result):
    """Format the struct analysis result into a clean markdown table."""
    lines = []
    lines.append("# 嵌入式固件结构体内存对齐与空洞深度分析报告\n")
    
    if "error" in result:
        lines.append(f"> [!WARNING]\n> {result['error']}")
        if "hint" in result:
            lines.append(f"> *提示*: {result['hint']}")
        return "\n".join(lines)
        
    if "queried_struct" in result:
        s = result["queried_struct"]
        lines.append(f"## 结构体专题深度解剖: `{s['name']}`\n")
        lines.append(f"- **分类**: {s['category']}")
        lines.append(f"- **声明定义**: `{s['decl_file']}:{s['decl_line']}`")
        lines.append(f"- **当前总大小**: `{s['total_size']}` Bytes (包含 `{s['hole_bytes']}` 字节对齐空洞, 浪费率 `{s['waste_percentage']}%`)")
        lines.append(f"- **贪心重排后大小**: `{s['repack_simulation']['repacked_size']}` Bytes (可节省 **`{s['repack_simulation']['bytes_saved']}`** 字节)\n")
        
        lines.append("### 当前成员内存偏移布局 (Memory Layout)")
        lines.append("| 偏移 (Offset) | 成员变量名 | 类型 | 大小 (Bytes) | 状态 / 空洞说明 |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        
        # Merge members and holes into offset view
        events = []
        for m in s["members"]:
            events.append({"offset": m["offset"], "type": "member", "data": m})
        for h in s["holes"]:
            events.append({"offset": h["offset"], "type": "hole", "data": h})
            events.sort(key=lambda x: (x["offset"], 0 if x["type"] == "member" else 1))
            
        for ev in events:
            if ev["type"] == "member":
                m = ev["data"]
                lines.append(f"| `+0x{m['offset']:02X}` ({m['offset']}) | `{m['name']}` | `{m['type_name']}` | {m['size']} B | 正常字段 |")
            else:
                h = ev["data"]
                lines.append(f"| `+0x{h['offset']:02X}` ({h['offset']}) | *[PADDING HOLE]* | - | **{h['hole_size']} B** | ⚠️ 对齐空隙 (在 `{h['after_member']}` 之后) |")
                
        if s["repack_simulation"]["bytes_saved"] > 0:
            lines.append("\n### 💡 AI 建议的优化重排代码 (零空洞紧凑布局)")
            lines.append("```c")
            lines.append(f"// 优化前大小: {s['total_size']} 字节 -> 优化后大小: {s['repack_simulation']['repacked_size']} 字节 (节省 {s['repack_simulation']['bytes_saved']} 字节)")
            lines.append(f"typedef struct {{")
            for nm in s["repack_simulation"]["new_layout"]:
                lines.append(f"    {nm['type']:<16} {nm['name']};  // Offset: +0x{nm['offset']:02X} ({nm['size']} B)")
            lines.append(f"}} {s['name']}_Optimized;")
            lines.append("```")
            
        return "\n".join(lines)
        
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


def evaluate_struct_gate(result, scope):
    """Filter struct findings against touched scope and evaluate gate verdict."""
    if "error" in result:
        return
        
    app_structs = result.get("top_wasteful_app_structs", [])
    new_blockers = []
    legacy_suppressed = []
    arch_hazards = []
    ai_heal_instructions = []
    
    for s in app_structs:
        is_touched = is_file_or_line_touched(s.get("decl_file"), s.get("decl_line"), scope)
        if is_touched:
            if s.get("hole_bytes", 0) > 0 and s["repack_simulation"].get("bytes_saved", 0) > 0:
                new_blockers.append(s)
                ai_heal_instructions.append(format_ai_heal_instruction(
                    "STRUCT_PADDING_HOLE",
                    s.get("decl_file"),
                    s.get("decl_line"),
                    f"Struct '{s['name']}' wastes {s['hole_bytes']} bytes ({s['waste_percentage']}%) in padding holes.",
                    "REPACK_STRUCT_4_2_1",
                    f"Struct '{s['name']}' contains alignment padding holes wasting {s['hole_bytes']} bytes. Reorder members in descending order of alignment (4-byte pointers/ints -> 2-byte shorts -> 1-byte chars) to save memory.",
                    patch=s["repack_simulation"].get("optimized_c_code")
                ))
        else:
            if s.get("hole_bytes", 0) >= 20 and s.get("waste_percentage", 0) >= 25.0:
                arch_hazards.append({
                    "type": "LEGACY_STRUCT_HOLE_HAZARD",
                    "struct": s["name"],
                    "message": f"Legacy struct '{s['name']}' wastes {s['hole_bytes']} B ({s['waste_percentage']}%) of RAM."
                })
            else:
                legacy_suppressed.append(s)
                
    gate = build_gate_verdict(new_blockers, [], legacy_suppressed, arch_hazards, scope)
    result["gate"] = gate
    result["new_wasteful_structs"] = new_blockers
    result["legacy_suppressed_structs"] = legacy_suppressed
    result["ai_heal_instructions"] = ai_heal_instructions


def format_markdown_report(result):
    """Format struct analysis results into clean Markdown report."""
    lines = []
    lines.append("# 嵌入式固件结构体内存对齐与空洞深度分析报告\n")
    
    if "error" in result:
        lines.append(f"> [!WARNING]\n> {result['error']}")
        return "\n".join(lines)
        
    gate = result.get("gate", {})
    verdict = gate.get("verdict", "PASSED")
    if verdict == "BLOCKED":
        lines.append(f"> [!CAUTION]\n> **🚨 嵌入式 AI 结构体对齐门禁拦截 (BLOCKED)**: {gate.get('summary', '')}\n")
    else:
        lines.append(f"> [!NOTE]\n> **✅ 嵌入式 AI 结构体对齐门禁通过 (PASSED)**: {gate.get('summary', '')}\n")
        
    summ = result["summary"]
    lines.append("## 1. 结构体内存浪费全景总览")
    lines.append(f"- **门禁判定结果**: **`{verdict}`** (Exit code: `{gate.get('exit_code', 0)}`)")
    lines.append(f"- **分析结构体总数**: `{summ['total_structs_analyzed']}` 个 (用户业务结构体: `{summ['app_structs_count']}` 个, 外设硬件寄存器: `{summ['hw_structs_count']}` 个)")
    if gate.get("is_incremental"):
        lines.append(f"- **🛡️ 老代码历史结构体空洞静默**: `{len(result.get('legacy_suppressed_structs', []))}` 个 (已跳过不阻断)")
    lines.append(f"- **存在空洞的用户结构体**: `{summ['app_structs_with_holes']}` 个")
    lines.append(f"- **用户业务结构体累计 Padding 浪费**: `{summ['total_app_wasted_bytes']}` 字节\n")
    
    new_wasteful = result.get("new_wasteful_structs", [])
    if new_wasteful:
        lines.append("## 2. 🚨 本次新增/修改的结构体空洞 (AI 需紧凑重排)")
        lines.append("| 结构体类型名称 | 当前大小 | 浪费空洞 | 浪费比例 | 重排可省内存 | 定义所在源码 |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for s in new_wasteful:
            sim = s["repack_simulation"]
            lines.append(
                f"| `{s['name']}` | **{s['total_size']} B** | `{s['hole_bytes']} B` | **{s['waste_percentage']}%** | 可省 `{sim['bytes_saved']} B` | `{s['decl_file']}:{s['decl_line']}` |"
            )
            
        if result.get("ai_heal_instructions"):
            lines.append("\n### 🤖 AI 重排建议与 C 补丁代码 (Auto-Heal Patches):")
            for h in result["ai_heal_instructions"]:
                lines.append(f"#### 结构体重排建议: `{h['file']}:{h['line']}`")
                lines.append(f"> {h['instruction']}\n")
                if h.get("suggested_patch"):
                    lines.append("```c")
                    lines.append(h["suggested_patch"])
                    lines.append("```\n")
    else:
        lines.append("## 2. 本次新增结构体对齐检查")
        lines.append("> [!NOTE]\n> ✅ 本次改动未引入存在对齐空洞的用户业务结构体，内存排布良好。\n")
        
    lines.append("\n## 3. 芯片外设硬件寄存器结构体分布 (Hardware Reference)")
    lines.append("| 外设寄存器结构体 | 物理占用 | 保留位空隙 (Reserved) | 声明文件 |")
    lines.append("| :--- | :--- | :--- | :--- |")
    for s in result["hardware_register_structs"][:10]:
        lines.append(f"| `{s['name']}` | `{s['total_size']} B` | `{s['hole_bytes']} B` | `{s['decl_file']}` |")
        
    return "\n".join(lines)


def auto_discover_elf(workspace_dir):
    """Auto-detect most recently modified ELF binary."""
    workspace = Path(workspace_dir).resolve()
    elf_files = []
    for root, _, files in os.walk(workspace):
        if any(skip in root for skip in ['.git', 'node_modules', '.gemini']):
            continue
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in ['.elf', '.axf', '.out']:
                elf_files.append(os.path.join(root, f))
    elf_files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return elf_files[0] if elf_files else None


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
    parser = argparse.ArgumentParser(description="Embedded Struct Padding & Alignment DWARF Analyzer")
    parser.add_argument("--workspace", "-w", default=".", help="Workspace root directory")
    parser.add_argument("--elf", "-e", help="Path to ELF binary with DWARF symbols")
    parser.add_argument("--query-struct", "-q", help="Deep dive into a specific struct name")
    parser.add_argument("--changed-files", nargs="*", help="Files modified by AI/current commit")
    parser.add_argument("--diff", nargs="?", const="HEAD", help="Use git diff to identify changed scope")
    parser.add_argument("--include-legacy", action="store_true", help="Include legacy technical debt in reports")
    parser.add_argument("--gate", action="store_true", help="Enforce quality gate exit code (1 on blocker, 2 on arch hazard)")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Console output format")
    parser.add_argument("--output-dir", help="Directory to save reports (default: <workspace>/reports)")
    parser.add_argument("--output", "-o", help="Custom output path or prefix")
    parser.add_argument("--no-save", action="store_true", help="Do not save reports to disk")
    
    args = parser.parse_args()
    workspace = os.path.abspath(args.workspace)
    elf_path = args.elf or auto_discover_elf(workspace)
    
    if not elf_path or not os.path.isfile(elf_path):
        sys.stderr.write(f"Error: ELF file not found. Please specify --elf or run in a directory containing an ELF binary.\n")
        sys.exit(1)
        
    scope = resolve_changed_scope(workspace, changed_files=args.changed_files, diff_ref=args.diff, include_legacy=args.include_legacy)
    
    res = analyze_struct_padding(elf_path, args.query_struct)
    evaluate_struct_gate(res, scope)
    
    md_report = format_markdown_report(res)
    reports_dir = args.output_dir or os.path.join(workspace, "reports")
    save_dual_reports(reports_dir, "report_structs", md_report, res, args.output, args.no_save)
    
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
