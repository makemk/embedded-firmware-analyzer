#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Embedded Memory Budget & Symbol Footprint Analyzer (ELF + MAP Engine)
Uses pyelftools and mapfile-parser to analyze Flash/SRAM allocation, top symbols,
subsystem code distribution, and symbol cross-referencing.
"""

import os
import sys
import json
import argparse
import re
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
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    ELFFile = None
    SymbolTableSection = None

try:
    import mapfile_parser
except ImportError:
    mapfile_parser = None


def auto_discover_elf_map(workspace_dir):
    """Auto-detect most recently built ELF and corresponding MAP file."""
    workspace = Path(workspace_dir).resolve()
    elf_files = []
    map_files = []
    
    for root, _, files in os.walk(workspace):
        if any(skip in root for skip in ['.git', 'node_modules', '.gemini']):
            continue
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in ['.elf', '.axf', '.out']:
                elf_files.append(os.path.join(root, f))
            elif ext == '.map':
                map_files.append(os.path.join(root, f))
                
    elf_files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    map_files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    
    best_elf = elf_files[0] if elf_files else None
    best_map = None
    
    if best_elf:
        elf_stem = Path(best_elf).stem.lower()
        elf_dir = Path(best_elf).parent
        for m in map_files:
            if Path(m).stem.lower() == elf_stem and Path(m).parent == elf_dir:
                best_map = m
                break
        if not best_map:
            for m in map_files:
                if Path(m).stem.lower() == elf_stem:
                    best_map = m
                    break
        if not best_map and map_files:
            best_map = map_files[0]
    elif map_files:
        best_map = map_files[0]
        
    return {"elf": best_elf, "map": best_map}


def analyze_elf_binary(elf_path):
    """Inspect ELF headers, loadable sections, and symbol table."""
    if not ELFFile:
        return {"error": "pyelftools is not installed."}
        
    if not os.path.isfile(elf_path):
        return {"error": f"ELF file not found: {elf_path}"}
        
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        header = elf.header
        
        target_info = {
            "machine": header['e_machine'],
            "type": header['e_type'],
            "entry": hex(header['e_entry']),
            "endianness": "little" if elf.little_endian else "big",
            "class": "32-bit" if elf.elfclass == 32 else "64-bit"
        }
        
        sections = []
        flash_total = 0
        ram_total = 0
        iram_total = 0
        code_total = 0
        rodata_total = 0
        data_total = 0
        bss_total = 0
        stack_heap_total = 0
        
        for sec in elf.iter_sections():
            flags = sec['sh_flags']
            # Only consider allocatable memory sections (SHF_ALLOC = 2)
            if flags & 2:
                addr = sec['sh_addr']
                size = sec['sh_size']
                name = sec.name
                
                sec_item = {
                    "name": name,
                    "addr": hex(addr),
                    "size": size,
                    "flags": hex(flags)
                }
                sections.append(sec_item)
                
                is_iram = (0x10000000 <= addr < 0x20000000)
                is_sram = (0x20000000 <= addr < 0x40000000)
                is_flash = (0x00000000 <= addr < 0x10000000) or (0x08000000 <= addr < 0x10000000)
                
                lower_name = name.lower()
                if "stack" in lower_name or "heap" in lower_name or "user_heap_stack" in lower_name:
                    stack_heap_total += size
                elif "bss" in lower_name:
                    bss_total += size
                elif "data" in lower_name:
                    data_total += size
                elif "rodata" in lower_name or "const" in lower_name or "vector" in lower_name:
                    rodata_total += size
                elif "text" in lower_name or "code" in lower_name:
                    code_total += size
                
                if is_sram:
                    ram_total += size
                elif is_iram:
                    iram_total += size
                elif is_flash:
                    flash_total += size
                    
        # Symbols
        symtab = elf.get_section_by_name('.symtab')
        funcs = []
        ram_vars = []
        
        if symtab and isinstance(symtab, SymbolTableSection):
            for sym in symtab.iter_symbols():
                sz = sym['st_size']
                addr = sym['st_value']
                st_type = sym['st_info']['type']
                st_bind = sym['st_info']['bind']
                name = sym.name
                
                if not name or sz == 0:
                    continue
                    
                sym_entry = {
                    "name": name,
                    "size": sz,
                    "addr": hex(addr),
                    "type": st_type,
                    "bind": st_bind
                }
                
                if st_type == 'STT_FUNC':
                    funcs.append(sym_entry)
                elif st_type == 'STT_OBJECT':
                    if 0x20000000 <= addr < 0x40000000:
                        ram_vars.append(sym_entry)
                        
        funcs.sort(key=lambda x: x['size'], reverse=True)
        ram_vars.sort(key=lambda x: x['size'], reverse=True)
        
        return {
            "target_info": target_info,
            "memory_totals": {
                "flash_bytes": flash_total,
                "ram_bytes": ram_total,
                "iram_bytes": iram_total,
                "breakdown": {
                    "code_bytes": code_total,
                    "rodata_bytes": rodata_total,
                    "data_bytes": data_total,
                    "bss_bytes": bss_total,
                    "stack_heap_bytes": stack_heap_total
                }
            },
            "sections": sections,
            "top_functions": funcs[:15],
            "top_ram_variables": ram_vars[:15]
        }


def analyze_map_contributions(map_path):
    """Decompose memory consumption by translation units (.o) and functional modules."""
    if not os.path.isfile(map_path):
        return {"error": f"MAP file not found: {map_path}"}
        
    file_contributions = defaultdict(lambda: {"flash": 0, "ram": 0})
    module_groups = defaultdict(lambda: {"flash": 0, "ram": 0, "files_count": 0})
    parsed_with_lib = False
    
    if mapfile_parser:
        try:
            mf = mapfile_parser.MapFile()
            mf.readMapFile(map_path)
            if mf._segmentsList:
                parsed_with_lib = True
                for seg in mf._segmentsList:
                    for sec in seg._sectionsList:
                        if sec.isFill or sec.size == 0:
                            continue
                        fpath_str = str(sec.filepath).replace('\\', '/')
                        vram = sec.vram
                        sz = sec.size
                        
                        if 0x20000000 <= vram < 0x40000000:
                            file_contributions[fpath_str]["ram"] += sz
                        else:
                            file_contributions[fpath_str]["flash"] += sz
        except Exception:
            parsed_with_lib = False
            
    if not parsed_with_lib or len(file_contributions) == 0:
        with open(map_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        pattern = re.compile(
            r'^\s+(\.[a-zA-Z0-9_\.\-]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\S+\.o|\S+\.a\(\S+\.o\))',
            re.MULTILINE
        )
        for m in pattern.finditer(content):
            sec, addr_s, sz_s, obj = m.groups()
            addr = int(addr_s, 16)
            sz = int(sz_s, 16)
            if sz == 0:
                continue
            obj_clean = obj.replace('\\', '/')
            if 0x20000000 <= addr < 0x40000000:
                file_contributions[obj_clean]["ram"] += sz
            else:
                file_contributions[obj_clean]["flash"] += sz
                
    for fpath, data in file_contributions.items():
        lower_p = fpath.lower()
        if 'app' in lower_p or 'main' in lower_p:
            group = "Application"
        elif 'bsp' in lower_p:
            group = "BSP (Board Support)"
        elif 'dsp' in lower_p:
            group = "DSP / Math Core"
        elif 'hal' in lower_p or 'mcu' in lower_p:
            group = "HAL / MCU Drivers"
        elif 'driver' in lower_p:
            group = "Device Drivers"
        elif 'cmsis' in lower_p or 'startup' in lower_p:
            group = "CMSIS / Startup"
        elif 'rtos' in lower_p or 'freertos' in lower_p:
            group = "RTOS Kernel"
        elif '.a(' in lower_p or 'libc' in lower_p or 'libm' in lower_p:
            group = "C Runtime Library"
        else:
            group = "Others / Utilities"
            
        module_groups[group]["flash"] += data["flash"]
        module_groups[group]["ram"] += data["ram"]
        module_groups[group]["files_count"] += 1
        
    top_files = sorted(
        [{"file": k, "flash": v["flash"], "ram": v["ram"]} for k, v in file_contributions.items()],
        key=lambda x: x["flash"] + x["ram"],
        reverse=True
    )
    
    return {
        "module_groups": dict(module_groups),
        "top_contributing_files": top_files[:15],
        "total_files_analyzed": len(file_contributions)
    }


def query_symbol_in_depth(symbol_name, elf_path, map_path, workspace_dir=None):
    """Deep dive into a specific symbol across ELF, MAP, and source references."""
    res = {
        "symbol": symbol_name,
        "found": False,
        "elf_info": None,
        "map_info": None,
        "source_references": []
    }
    
    if elf_path and os.path.isfile(elf_path) and ELFFile:
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name('.symtab')
            if symtab:
                for sym in symtab.iter_symbols():
                    if sym.name == symbol_name:
                        addr = sym['st_value']
                        sz = sym['st_size']
                        res["elf_info"] = {
                            "name": sym.name,
                            "addr": hex(addr),
                            "size": sz,
                            "type": sym['st_info']['type'],
                            "bind": sym['st_info']['bind'],
                            "memory_region": "RAM" if (0x20000000 <= addr < 0x40000000) else "Flash/ROM"
                        }
                        res["found"] = True
                        break
                        
    if map_path and os.path.isfile(map_path) and mapfile_parser:
        try:
            mf = mapfile_parser.MapFile()
            mf.readMapFile(map_path)
            found = mf.findSymbolByName(symbol_name)
            if found:
                res["map_info"] = {
                    "object_file": str(found.section.filepath),
                    "section_type": found.section.sectionType,
                    "vram": hex(found.symbol.vram),
                    "size": found.symbol.size
                }
                res["found"] = True
        except Exception:
            pass
            
    if workspace_dir and os.path.isdir(workspace_dir):
        sym_pattern = re.compile(rf'\b{re.escape(symbol_name)}\b')
        for root, _, files in os.walk(workspace_dir):
            if any(skip in root for skip in ['.git', 'build', 'node_modules', '.gemini']):
                continue
            for fname in files:
                if fname.endswith(('.c', '.h', '.cpp', '.hpp', '.s', '.S')):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as sf:
                            for idx, line in enumerate(sf, 1):
                                if sym_pattern.search(line):
                                    rel_p = os.path.relpath(fpath, workspace_dir)
                                    res["source_references"].append({
                                        "file": rel_p.replace('\\', '/'),
                                        "line": idx,
                                        "content": line.strip()
                                    })
                    except Exception:
                        pass
                        
    return res


def format_markdown_report(result):
    """Format memory budget results into clean Markdown."""
    lines = []
    lines.append("# 嵌入式固件内存预算与符号分布分析报告\n")
    
    if "elf" in result and "target_info" in result["elf"]:
        tgt = result["elf"]["target_info"]
        lines.append("## 1. 目标平台与硬件架构")
        lines.append(f"- **目标芯片架构**: `{tgt.get('machine', 'ARM')}` ({tgt.get('class')}, {tgt.get('endianness')}-endian)")
        lines.append(f"- **复位入口地址**: `{tgt.get('entry')}`\n")
        
    if "elf" in result and "memory_totals" in result["elf"]:
        mem = result["elf"]["memory_totals"]
        f_kb = mem["flash_bytes"] / 1024.0
        r_kb = mem["ram_bytes"] / 1024.0
        i_kb = mem["iram_bytes"] / 1024.0
        bd = mem.get("breakdown", {})
        
        lines.append("## 2. 物理内存预算与分配全景 (Memory Budget)")
        lines.append("| 存储介质 / 区域 | 物理占用字节 (Bytes) | 占用容量 (KB) | 详细构成与说明 |")
        lines.append("| :--- | :--- | :--- | :--- |")
        lines.append(f"| **Flash (ROM)** | `{mem['flash_bytes']:,}` | **`{f_kb:.2f} KB`** | `.text` 机器代码 + `.rodata` 常量 + 中断向量 |")
        lines.append(f"| **SRAM (Data)** | `{mem['ram_bytes']:,}` | **`{r_kb:.2f} KB`** | `.data` 初值 + `.bss` 零初始化 + 堆栈预留 |")
        if mem["iram_bytes"] > 0:
            lines.append(f"| **IRAM / TCM** | `{mem['iram_bytes']:,}` | **`{i_kb:.2f} KB`** | 零等待高速指令 RAM (`.ramcode`) |")
        lines.append(f"| ├─ 代码段 (`.text`) | `{bd.get('code_bytes', 0):,}` | {bd.get('code_bytes', 0)/1024.0:.2f} KB | 编译机器指令 |")
        lines.append(f"| ├─ 只读常量 (`.rodata`) | `{bd.get('rodata_bytes', 0):,}` | {bd.get('rodata_bytes', 0)/1024.0:.2f} KB | 字符串、查表、校验和 |")
        lines.append(f"| ├─ 堆栈预留 (Stack/Heap) | `{bd.get('stack_heap_bytes', 0):,}` | {bd.get('stack_heap_bytes', 0)/1024.0:.2f} KB | 运行时局部变量与调用栈深度保障 |")
        
    # Top SRAM
    if "elf" in result and "top_ram_variables" in result["elf"]:
        lines.append("\n## 3. SRAM 内存消耗 Top 10 (全局与静态变量)")
        lines.append("| 变量 / 符号名称 | 占用大小 (Bytes) | 内存绝对地址 (VMA) | 绑定类型 |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for v in result["elf"]["top_ram_variables"][:10]:
            lines.append(f"| `{v['name']}` | **`{v['size']} B`** ({v['size']/1024.0:.2f} KB) | `{v['addr']}` | `{v['bind']}` |")
            
    # Top Flash
    if "elf" in result and "top_functions" in result["elf"]:
        lines.append("\n## 4. Flash 代码体积消耗 Top 10 函数")
        lines.append("| 函数名称 | 代码大小 (Bytes) | 内存地址 (VMA) | 优化关注点 |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for f in result["elf"]["top_functions"][:10]:
            lines.append(f"| `{f['name']}` | **`{f['size']} B`** ({f['size']/1024.0:.2f} KB) | `{f['addr']}` | 检查内联展开与死代码 |")
            
    # Subsystems
    if "map" in result and "module_groups" in result["map"]:
        mods = result["map"]["module_groups"]
        lines.append("\n## 5. 固件子系统体积分布 (Subsystem Breakdown)")
        lines.append("| 子系统模块 | Flash 占用 (KB) | RAM 占用 (KB) | 目标文件数 |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for m_name, m_val in sorted(mods.items(), key=lambda x: x[1]['flash'] + x[1]['ram'], reverse=True):
            f_k = m_val["flash"] / 1024.0
            r_k = m_val["ram"] / 1024.0
            lines.append(f"| **{m_name}** | `{f_k:.2f} KB` | `{r_k:.2f} KB` | {m_val['files_count']} |")
            
    # Symbol query
    if "symbol_query" in result and result["symbol_query"].get("found"):
        sq = result["symbol_query"]
        lines.append(f"\n## 6. 符号专题深度剖析: `{sq['symbol']}`")
        if sq.get("elf_info"):
            ei = sq["elf_info"]
            lines.append(f"- **物理存储区域**: {ei['memory_region']} (`{ei['addr']}`)")
            lines.append(f"- **占用大小**: `{ei['size']}` 字节 ({ei['size']/1024.0:.2f} KB)")
        if sq.get("map_info"):
            mi = sq["map_info"]
            lines.append(f"- **定义所在目标文件**: `{mi['object_file']}`")
            lines.append(f"- **所属 Section**: `{mi['section_type']}`")
        if sq.get("source_references"):
            lines.append(f"- **源码引用定位 ({len(sq['source_references'])} 处)**:")
            for r in sq["source_references"][:10]:
                lines.append(f"  - `{r['file']}:{r['line']}`: `{r['content']}`")
                
    return "\n".join(lines)


try:
    from embedded_ocr_common import build_gate_verdict, format_ai_heal_instruction
except ImportError:
    script_dir = Path(__file__).resolve().parent
    sys.path.insert(0, str(script_dir))
    from embedded_ocr_common import build_gate_verdict, format_ai_heal_instruction


def evaluate_memory_gate(report):
    """Evaluate architectural memory budget gate."""
    arch_hazards = []
    elf_data = report.get("elf", {})
    totals = elf_data.get("memory_totals", {})
    ram_bytes = totals.get("ram_bytes", 0)
    
    # Check if SRAM allocation exceeds 85% safe capacity threshold (assume 64KB for ADuCM430)
    if ram_bytes > 58000:
        arch_hazards.append({
            "type": "SRAM_EXHAUSTION_HAZARD",
            "message": f"SRAM allocation ({ram_bytes} bytes) exceeds 85% safe capacity threshold."
        })
        
    gate = build_gate_verdict([], [], [], arch_hazards, {"is_incremental": False})
    report["gate"] = gate


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
    parser = argparse.ArgumentParser(description="Embedded Memory Budget & Symbol Footprint Analyzer")
    parser.add_argument("--workspace", "-w", default=".", help="Workspace root directory")
    parser.add_argument("--elf", help="Path to .elf/.axf file")
    parser.add_argument("--map", help="Path to .map file")
    parser.add_argument("--query-symbol", "-q", help="Deep dive into a specific symbol name")
    parser.add_argument("--gate", action="store_true", help="Enforce architectural memory gate")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Console output format")
    parser.add_argument("--output-dir", help="Directory to save reports (default: <workspace>/reports)")
    parser.add_argument("--output", "-o", help="Custom output path or prefix")
    parser.add_argument("--no-save", action="store_true", help="Do not save reports to disk")
    
    args = parser.parse_args()
    workspace = os.path.abspath(args.workspace)
    
    auto = auto_discover_elf_map(workspace)
    elf_path = args.elf or auto["elf"]
    map_path = args.map or auto["map"]
    
    report = {
        "workspace": workspace,
        "elf_path": elf_path,
        "map_path": map_path
    }
    
    if elf_path:
        report["elf"] = analyze_elf_binary(elf_path)
    if map_path:
        report["map"] = analyze_map_contributions(map_path)
    if args.query_symbol:
        report["symbol_query"] = query_symbol_in_depth(args.query_symbol, elf_path, map_path, workspace)
        
    evaluate_memory_gate(report)
    
    md_report = format_markdown_report(report)
    reports_dir = args.output_dir or os.path.join(workspace, "reports")
    save_dual_reports(reports_dir, "report_memory", md_report, report, args.output, args.no_save)
    
    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(md_report)
        
    if args.gate and "gate" in report:
        exit_code = report["gate"].get("exit_code", 0)
        if exit_code != 0:
            sys.exit(exit_code)


if __name__ == "__main__":
    main()

