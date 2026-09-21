#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Optical Module CMIS Protocol Analyzer (cmis_protocol_analyzer.py)
A decoupled, pluggable analyzer for Optical Transceiver CMIS / SFF-8636 firmware.
Uses Parent-Child Configuration Architecture:
  Parent Base Spec: rules/cmis_spec_rules.json (Immutable industry ontology)
  Child Project Profile: <workspace>/cmis_project_profile.json (Auto-discovered project bindings)

Key Optical Guardrails:
1. [BLOCKER] CMIS_MISSING_ENDIAN_SWAP: 16-bit DDM telemetry written without Big-Endian swap.
2. [BLOCKER] CMIS_I2C_ISR_LONG_LATENCY: Blocking/slow calls inside I2C slave RX/TX context.
3. [CRITICAL] CMIS_RO_PAGE_CORRUPTION: Direct unauthorized writes to Page 00h or Lower Page 0~25 RO region.
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

DEFAULT_PARENT_RULES_PATH = script_dir.parent / 'rules' / 'cmis_spec_rules.json'


# ==============================================================================
# 1. Parent-Child Configuration Engine
# ==============================================================================

def load_parent_rules(parent_path=None):
    """Load the base immutable CMIS specification rules."""
    path = Path(parent_path) if parent_path else DEFAULT_PARENT_RULES_PATH
    if not path.exists():
        # Fallback inline basic parent rules if file missing
        return {
            "telemetry_16bit": {
                "semantic_fields": [
                    "temp", "temperature", "montemp", "temp_c",
                    "volt", "voltage", "monvolt", "vcc",
                    "bias", "monbias", "tx_bias", "laser_bias",
                    "tx_?pwr", "rx_?pwr", "tx_?po", "rx_?po", "montxpo", "monrxpo", "opt_pwr",
                    "aux[1-3]", "monaux[1-3]"
                ],
                "recognized_swap_signatures": [
                    "SwapU16", "SwapS16", "SwapU32", "SwapS32",
                    "__REV16", "__REV", "REV16", "htons", "ntohs", "bswap16"
                ]
            },
            "i2c_slave_timing": {
                "forbidden_in_isr": [
                    "flash_write", "flash_erase", "spi_flash_download", "eeprom_write",
                    "delay", "sleep", "msleep", "usleep", "printf"
                ]
            },
            "clear_on_read_and_interrupt": {
                "semantic_rules": {
                    "latch_operation": "bitwise_or",
                    "cor_requires_intl_update": True
                }
            }
        }
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def discover_project_profile(workspace_dir, parent_rules):
    """
    Intelligently scan workspace files and auto-generate cmis_project_profile.json
    adapting to the current project's concrete symbols and macros.
    """
    workspace = Path(workspace_dir).resolve()
    c_files = []
    for root, _, files in os.walk(workspace):
        if any(skip in root.lower() for skip in ['.git', 'node_modules', '.gemini', 'build']):
            continue
        for f in files:
            if f.endswith(('.c', '.h')):
                c_files.append(os.path.join(root, f))

    detected_headers = []
    detected_swap_macros = set()
    detected_ddm_pointers = set()
    detected_i2c_handlers = set()
    detected_page_buffers = set()
    detected_rdc_handlers = set()
    detected_intl_updaters = set()
    detected_latched_buffers = set()
    detected_realtime_buffers = set()
    detected_id_pointers = set()
    detected_page00_buffers = set()
    detected_psw_vars = set()
    detected_tabsel_vars = set()
    detected_txdis_symbols = set()
    detected_lpmode_symbols = set()
    detected_cdb_symbols = set()
    detected_busy_guards = set()
    detected_flash_isolators = set()
    detected_pid_funcs = set()
    detected_cali_funcs = set()
    detected_lut_funcs = set()
    detected_boot_funcs = set()

    swap_sig_patterns = [re.compile(r'\b' + re.escape(sig) + r'\b') for sig in parent_rules['telemetry_16bit']['recognized_swap_signatures']]
    swap_def_pattern = re.compile(r'#define\s+([A-Za-z0-9_]*swap[A-Za-z0-9_]*)\s*\(', re.IGNORECASE)

    # Patterns for COR & Interrupt architecture
    rdc_pattern = re.compile(r'\bvoid\s+([A-Za-z0-9_]*(?:_rdc|rdc_|rd_clr|rdclr|clear_on_read|i2cs_rdc|msa_rdc)[A-Za-z0-9_]*)\s*\(', re.IGNORECASE)
    intl_pattern = re.compile(r'\bvoid\s+([A-Za-z0-9_]*(?:UpdtIntL|Updt_Int|update_intl|IO_INTL|intl_update)[A-Za-z0-9_]*)\s*\(', re.IGNORECASE)
    latched_buf_pattern = re.compile(r'\b(SffLow|SffT11|SffT10|L_ModFlgs|L_LanFlgs|L_FlgSum)\b')
    realtime_buf_pattern = re.compile(r'\b(g_StatFlgs|stRtDDM|stGlbSta|stLanSta)\b')

    # Patterns for Directions 1~5
    id_pattern = re.compile(r'\b([A-Za-z0-9_]+)\s*\*\s*(psIDInfo|psQddP02|psTab80|psTab81|psTab83)\b')
    page00_pattern = re.compile(r'\b(SffT00|SffT01|SffT02|psIDInfo)\b')
    psw_pattern = re.compile(r'\b([A-Za-z0-9_]*Psw_Mod[A-Za-z0-9_]*|PSW_MOD_[A-Za-z0-9_]+)\b')
    tabsel_pattern = re.compile(r'\b([A-Za-z0-9_]*TabSel[A-Za-z0-9_]*)\b')
    txdis_pattern = re.compile(r'\b([A-Za-z0-9_]*(?:TxDis|TxOutDis|bsp_tx_dis|TxFltFlg|TxLosFlg)[A-Za-z0-9_]*)\b')
    lpmode_pattern = re.compile(r'\b([A-Za-z0-9_]*(?:bsp_lpmode|G_LPwrS_R|G_LPwrExS_R|SwLoPwr|HwLPwrEn)[A-Za-z0-9_]*)\b')
    cdb_pattern = re.compile(r'\b([A-Za-z0-9_]*(?:CdbStat|CBDStat|CdbIsBusy|CDBCompF[12])[A-Za-z0-9_]*)\b')

    # Patterns for Directions 6~11 (Production Robustness)
    busy_guard_pattern = re.compile(r'\b(?:void\s+)?([A-Za-z0-9_]*(?:wait_i2c_busy|i2c_busy_wait|wait_i2c_free|i2c_wait_busy)[A-Za-z0-9_]*)\s*\(', re.IGNORECASE)
    flash_iso_pattern = re.compile(r'\b([A-Za-z0-9_]*(?:mcu_i2cs_en|i2c_slave_en|NVIC_DisableIRQ)[A-Za-z0-9_]*)\b')
    pid_func_pattern = re.compile(r'\b([A-Za-z0-9_]*(?:ATCCalculate|tec_ctrl|pid_calc|TecControl)[A-Za-z0-9_]*)\b', re.IGNORECASE)
    cali_func_pattern = re.compile(r'\b([A-Za-z0-9_]*(?:CaliMonSVal|CaliMonUVal|CaliMonFVal|bsp_cali)[A-Za-z0-9_]*)\b', re.IGNORECASE)
    lut_func_pattern = re.compile(r'\b([A-Za-z0-9_]*(?:bsp_lut_comp|lut_comp|lut_calc)[A-Za-z0-9_]*)\b', re.IGNORECASE)
    boot_func_pattern = re.compile(r'\b([A-Za-z0-9_]*(?:bsp_boot_jump|mcu_startboot|jump_to_boot)[A-Za-z0-9_]*)\b', re.IGNORECASE)

    for f_path in c_files:
        fname = os.path.basename(f_path).lower()
        if any(keyword in fname for keyword in ['msa', 'qdd', 'cmis', 'sff']):
            rel_h = os.path.relpath(f_path, workspace).replace('\\', '/')
            detected_headers.append(rel_h)

        try:
            with open(f_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue

        for m in swap_def_pattern.finditer(content):
            detected_swap_macros.add(m.group(1))

        for pat in swap_sig_patterns:
            if pat.search(content):
                detected_swap_macros.add(pat.pattern.replace('\\b', ''))

        pointer_pattern = re.compile(r'([A-Za-z0-9_]+)\s*\*\s*([A-Za-z0-9_]+)\s*=\s*\([^)]*\)\s*([A-Za-z0-9_]+)')
        for m in pointer_pattern.finditer(content):
            type_name = m.group(1)
            var_name = m.group(2)
            buf_name = m.group(3)
            if any(k in type_name.lower() or k in var_name.lower() or k in buf_name.lower() for k in ['ddm', 'msa', 'qdd', 'cmis', 'sff', 'p10', 'p11', 'p13', 'p00']):
                detected_ddm_pointers.add(var_name)
                detected_page_buffers.add(buf_name)

        isr_pattern = re.compile(r'\bvoid\s+([A-Za-z0-9_]*(?:i2c[0-9]*_slave|i2cs_rx|i2cs_tx|cmis_rx|cmis_tx|msa_rx|msa_tx)[A-Za-z0-9_]*)\s*\(', re.IGNORECASE)
        for m in isr_pattern.finditer(content):
            detected_i2c_handlers.add(m.group(1))

        for m in rdc_pattern.finditer(content):
            detected_rdc_handlers.add(m.group(1))

        for m in intl_pattern.finditer(content):
            detected_intl_updaters.add(m.group(1))

        for m in latched_buf_pattern.finditer(content):
            detected_latched_buffers.add(m.group(1))

        for m in realtime_buf_pattern.finditer(content):
            detected_realtime_buffers.add(m.group(1))

        for m in id_pattern.finditer(content):
            detected_id_pointers.add(m.group(2))

        for m in page00_pattern.finditer(content):
            detected_page00_buffers.add(m.group(1))

        for m in psw_pattern.finditer(content):
            detected_psw_vars.add(m.group(1))

        for m in tabsel_pattern.finditer(content):
            detected_tabsel_vars.add(m.group(1))

        for m in txdis_pattern.finditer(content):
            detected_txdis_symbols.add(m.group(1))

        for m in lpmode_pattern.finditer(content):
            detected_lpmode_symbols.add(m.group(1))

        for m in cdb_pattern.finditer(content):
            detected_cdb_symbols.add(m.group(1))

        for m in busy_guard_pattern.finditer(content):
            detected_busy_guards.add(m.group(1))

        for m in flash_iso_pattern.finditer(content):
            detected_flash_isolators.add(m.group(1))

        for m in pid_func_pattern.finditer(content):
            detected_pid_funcs.add(m.group(1))

        for m in cali_func_pattern.finditer(content):
            detected_cali_funcs.add(m.group(1))

        for m in lut_func_pattern.finditer(content):
            detected_lut_funcs.add(m.group(1))

        for m in boot_func_pattern.finditer(content):
            detected_boot_funcs.add(m.group(1))

    preferred_swap = "SwapU16" if "SwapU16" in detected_swap_macros else ("__REV16" if "__REV16" in detected_swap_macros else "SwapU16")

    child_profile = {
        "$schema": "cmis_project_profile_schema",
        "inherits": "cmis_spec_rules.json",
        "project_name": workspace.name,
        "auto_generated": True,
        "optical_spec": "QSFP-DD CMIS / SFF-8636",
        "detected_headers": sorted(detected_headers)[:8],
        "bindings": {
            "preferred_swap_macro": preferred_swap,
            "detected_swap_macros": sorted(list(detected_swap_macros)),
            "ddm_table_pointers": sorted(list(detected_ddm_pointers)) if detected_ddm_pointers else ["psDDMTab", "psQddP10", "psQddP11"],
            "page_buffer_arrays": sorted(list(detected_page_buffers)) if detected_page_buffers else ["SffLow", "SffT00", "SffT10", "SffT11"],
            "i2c_slave_handlers": sorted(list(detected_i2c_handlers)) if detected_i2c_handlers else ["I2C0_Slave_Int_Handler", "bsp_i2cs_rx", "bsp_i2cs_tx"],
            "rdc_handlers": sorted(list(detected_rdc_handlers)) if detected_rdc_handlers else ["bsp_i2cs_rdc"],
            "intl_updaters": sorted(list(detected_intl_updaters)) if detected_intl_updaters else ["UpdtIntL"],
            "latched_flag_buffers": sorted(list(detected_latched_buffers)) if detected_latched_buffers else ["SffLow", "SffT11", "L_ModFlgs", "L_LanFlgs"],
            "realtime_flag_buffers": sorted(list(detected_realtime_buffers)) if detected_realtime_buffers else ["g_StatFlgs", "stRtDDM"],
            "id_table_pointers": sorted(list(detected_id_pointers)) if detected_id_pointers else ["psIDInfo", "psQddP02"],
            "page00_buffers": sorted(list(detected_page00_buffers)) if detected_page00_buffers else ["SffT00"],
            "password_state_vars": sorted(list(detected_psw_vars)) if detected_psw_vars else ["Psw_Mod"],
            "page_select_vars": sorted(list(detected_tabsel_vars)) if detected_tabsel_vars else ["TabSel"],
            "tx_disable_symbols": sorted(list(detected_txdis_symbols)) if detected_txdis_symbols else ["bsp_tx_dis", "TxDis", "TxOutDis"],
            "lpmode_symbols": sorted(list(detected_lpmode_symbols)) if detected_lpmode_symbols else ["bsp_lpmode", "G_LPwrS_R"],
            "cdb_symbols": sorted(list(detected_cdb_symbols)) if detected_cdb_symbols else ["CdbStat", "CBDStat"],
            "busy_guard_funcs": sorted(list(detected_busy_guards)) if detected_busy_guards else ["wait_i2c_busy"],
            "flash_isolation_funcs": sorted(list(detected_flash_isolators)) if detected_flash_isolators else ["mcu_i2cs_en"],
            "pid_calc_funcs": sorted(list(detected_pid_funcs)) if detected_pid_funcs else ["ATCCalculate"],
            "cali_funcs": sorted(list(detected_cali_funcs)) if detected_cali_funcs else ["CaliMonSVal", "CaliMonUVal"],
            "lut_comp_funcs": sorted(list(detected_lut_funcs)) if detected_lut_funcs else ["bsp_lut_comp"],
            "boot_jump_funcs": sorted(list(detected_boot_funcs)) if detected_boot_funcs else ["bsp_boot_jump", "mcu_startboot"]
        }
    }
    return child_profile


def get_effective_rules(workspace_dir, force_profile=False):
    """
    Load base parent rules and overlay project child profile.
    If cmis_project_profile.json doesn't exist or force_profile is True, generates it.
    """
    parent = load_parent_rules()
    profile_path = Path(workspace_dir).resolve() / 'cmis_project_profile.json'

    if force_profile or not profile_path.exists():
        child = discover_project_profile(workspace_dir, parent)
        with open(profile_path, 'w', encoding='utf-8') as f:
            json.dump(child, f, indent=2, ensure_ascii=False)
        print(f"✨ [CMIS Profile] Generated project child configuration: {profile_path}")
    else:
        try:
            with open(profile_path, 'r', encoding='utf-8') as f:
                child = json.load(f)
        except Exception:
            child = discover_project_profile(workspace_dir, parent)

    return parent, child


# ==============================================================================
# 2. CMIS Protocol Auditing Engine
# ==============================================================================

def strip_c_comments(code):
    def replacer(match):
        s = match.group(0)
        return '\n' * s.count('\n') if s.startswith('/') else s
    return re.sub(r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"', replacer, code, flags=re.DOTALL | re.MULTILINE)


def audit_cmis_in_file(file_path, parent_rules, child_profile):
    """Audit a single C/H file against CMIS protocol rules."""
    issues = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_lines = f.readlines()
    except Exception:
        return issues

    bindings = child_profile.get('bindings', {})
    ddm_pointers = bindings.get('ddm_table_pointers', ["psDDMTab", "psQddP10", "psQddP11"])
    swap_macros = set(bindings.get('detected_swap_macros', ["SwapU16", "SwapS16", "__REV16", "htons"]))
    pref_swap = bindings.get('preferred_swap_macro', "SwapU16")
    i2c_handlers = set(bindings.get('i2c_slave_handlers', ["I2C0_Slave_Int_Handler", "bsp_i2cs_rx", "bsp_i2cs_tx"]))
    rdc_handlers = set(bindings.get('rdc_handlers', ["bsp_i2cs_rdc"]))
    intl_updaters = set(bindings.get('intl_updaters', ["UpdtIntL"]))
    latched_buffers = bindings.get('latched_flag_buffers', ["SffLow", "SffT11", "L_ModFlgs", "L_LanFlgs"])
    realtime_buffers = bindings.get('realtime_flag_buffers', ["g_StatFlgs", "stRtDDM"])
    forbidden_in_isr = parent_rules.get('i2c_slave_timing', {}).get('forbidden_in_isr', [])

    # Semantic pattern for DDM telemetry fields: MonTemp, MonVolt, MonBias, MonTxPo, MonRxPo, etc.
    semantic_list = parent_rules['telemetry_16bit']['semantic_fields']
    telemetry_field_pattern = re.compile(r'\b(' + '|'.join(semantic_list) + r')\b', re.IGNORECASE)

    # Build regex for DDM assignments: e.g. psDDMTab->MonTemp = ... OR psQddP11->MonBias[ch] = ...
    ptr_prefix = '|'.join(re.escape(p) for p in ddm_pointers) if ddm_pointers else r'ps[A-Za-z0-9_]+'
    ddm_assign_pattern = re.compile(
        r'((?:' + ptr_prefix + r')\s*->\s*([A-Za-z0-9_]+)(?:\[[^\]]*\])?)\s*=\s*([^;]+);'
    )

    # COR / Latch patterns
    flag_ptr_pattern = re.compile(r'\b([A-Za-z0-9_]+->L_[A-Za-z0-9_]+)\s*(?<![|<>=!&+-])=\s*(?![=])([^;]+);')
    buf_flag_pattern = re.compile(
        r'\b(' + '|'.join(re.escape(b) for b in latched_buffers) + r')\s*\[[^\]]+\]\s*(?<![|<>=!&+-])=\s*(?![=])([^;]*(?:' +
        '|'.join(re.escape(r) for r in realtime_buffers) + r'|Stat|Flg|Alm|Warn)[^;]*);',
        re.IGNORECASE
    )
    blind_zero_pattern = re.compile(r'\b(' + '|'.join(re.escape(b) for b in latched_buffers) + r')\s*\[[^\]]+\]\s*=\s*0x?0+\s*;')

    in_i2c_context = False
    in_rdc_context = False
    current_func_name = ""
    func_brace_depth = 0
    func_start_line = 0
    func_body_opened = False
    rdc_modified_latched = False
    rdc_called_intl = False
    recent_lines = []
    current_func_lines = []

    for line_no, raw_line in enumerate(raw_lines, 1):
        clean_line = re.sub(r'//.*$', '', raw_line).strip()

        # Track function header if at top level
        if not current_func_name and func_brace_depth == 0:
            func_match = re.match(r'^(?:void|uint8_t|int16_t|int32_t|int|uint16_t|uint32_t|bool)\s+([A-Za-z0-9_]+)\s*\([^;)]*\)', clean_line)
            if func_match:
                current_func_name = func_match.group(1)
                func_start_line = line_no
                func_body_opened = False
                in_i2c_context = current_func_name in i2c_handlers
                in_rdc_context = current_func_name in rdc_handlers
                rdc_modified_latched = False
                rdc_called_intl = False

        if current_func_name:
            if '{' in clean_line:
                func_body_opened = True
            open_b = clean_line.count('{')
            close_b = clean_line.count('}')
            func_brace_depth += open_b - close_b

            if in_rdc_context:
                if any(buf in clean_line for buf in latched_buffers) and '=' in clean_line:
                    rdc_modified_latched = True
                    if blind_zero_pattern.search(clean_line):
                        issues.append({
                            'rule_id': 'CMIS_COR_BLIND_ZERO_HAZARD',
                            'severity': 'WARNING',
                            'file': os.path.normpath(file_path),
                            'line': line_no,
                            'target': current_func_name,
                            'message': f"Blind zeroing ('= 0') to latched flag buffer in Clear-on-Read handler '{current_func_name}()'! If the physical fault condition remains active, blindly zeroing the register causes high-frequency interrupt flapping.",
                            'action': 'RESTORE_REALTIME_FLAG',
                            'suggested_fix': f"Restore from real-time status buffer (e.g. 'g_StatFlgs') rather than hardcoding '0'."
                        })
                if any(re.search(r'\b' + re.escape(upd) + r'\s*\(', clean_line) for upd in intl_updaters):
                    rdc_called_intl = True

            if func_body_opened and func_brace_depth <= 0:
                # Function body completed - perform whole-function CMIS semantic checks
                func_text = '\n'.join(current_func_lines)

                # Rule 4: Missing IntL update in RDC handler
                if in_rdc_context and rdc_modified_latched and not rdc_called_intl:
                    issues.append({
                        'rule_id': 'CMIS_COR_MISSING_INTL_UPDATE',
                        'severity': 'CRITICAL',
                        'file': os.path.normpath(file_path),
                        'line': func_start_line,
                        'target': current_func_name,
                        'message': f"Clear-on-Read handler '{current_func_name}()' modifies latched flag registers but fails to call an Interrupt update function ('{', '.join(intl_updaters)}') before returning! This causes the IntL hardware line to remain stuck low indefinitely, triggering switch port flapping.",
                        'action': 'ADD_INTL_UPDATE',
                        'suggested_fix': f"Call '{list(intl_updaters)[0]}()' before returning from '{current_func_name}()' when flags are updated."
                    })

                # Rule 6: Page dispatch switch missing safe default (for page read/transmit)
                if re.search(r'\bswitch\s*\(\s*(?:[A-Za-z0-9_]+->)?TabSel\s*\)', func_text):
                    is_read_dispatch = ('p_tdat' in func_text or '_tdat' in func_text or 'tx' in current_func_name.lower())
                    if is_read_dispatch:
                        has_safe_default = ('default:' in func_text) or ('*p_tdat = 0' in func_text) or ('*p_tdat = 0x00' in func_text)
                        if not has_safe_default:
                            issues.append({
                                'rule_id': 'CMIS_PAGE_TABLE_DEFAULT_MISSING',
                                'severity': 'CRITICAL',
                                'file': os.path.normpath(file_path),
                                'line': func_start_line,
                                'target': 'TabSel',
                                'message': f"Page dispatch switch in read context '{current_func_name}()' lacks safe default fallback! CMIS requires reading unmapped/unknown pages to return 0x00 rather than undefined buffer data or wild pointer dereferences.",
                                'action': 'ADD_PAGE_SWITCH_DEFAULT',
                                'suggested_fix': "Add '*p_tdat = 0x00;' before switch(TabSel) or add 'default: *p_tdat = 0x00; break;'."
                            })

                # Rule 7: Tx Disable missing TxFault interlock
                if ('bsp_tx_dis' in func_text or 'stGlbSet.TxDis' in func_text) and ('txdis' in func_text or 'TxOutDis' in func_text):
                    has_fault_interlock = any(k in func_text for k in ['TxFltFlg', 'TxFault', 'stRtDDM.TxFltFlg', 'stGlbSet.TxDis'])
                    if not has_fault_interlock:
                        issues.append({
                            'rule_id': 'CMIS_TX_FAULT_INTERLOCK_MISSING',
                            'severity': 'CRITICAL',
                            'file': os.path.normpath(file_path),
                            'line': func_start_line,
                            'target': 'txdis',
                            'message': f"Channel Tx_Disable logic in '{current_func_name}()' fails to force-disable channels upon TxFltFlg! Laser safety regulations (Class 1) require automatic fast shutdown when optical/electrical fault is detected.",
                            'action': 'ADD_TX_FAULT_INTERLOCK',
                            'suggested_fix': "Include 'txdis |= stRtDDM.TxFltFlg;' or evaluate 'stGlbSet.TxDis' before calling bsp_tx_dis."
                        })

                # --------------------------------------------------------------
                # Production Robustness Rules (Directions 6~11)
                # --------------------------------------------------------------
                fname_lower = current_func_name.lower()

                # Rule 9: PID Step and DAC Clamping Check
                if (('calculate' in fname_lower and any(k in fname_lower for k in ['tec', 'atc', 'pid'])) or
                    ('proportion *' in func_text.lower() and 'integral *' in func_text.lower())):
                    has_step = any(k in func_text for k in ['HMaxStep', 'CMaxStep', 'MaxStep', 'StepLimit', 'step_limit'])
                    has_dac = any(k in func_text for k in ['MaxDAC', 'MinDAC', 'DAC_MAX', 'DAC_MIN', 'dac_max', 'SATURATE'])
                    if not (has_step and has_dac):
                        issues.append({
                            'rule_id': 'EMBEDDED_PID_OUTPUT_CLAMPING',
                            'severity': 'CRITICAL',
                            'file': os.path.normpath(file_path),
                            'line': func_start_line,
                            'target': current_func_name,
                            'message': f"PID control loop in '{current_func_name}()' lacks dual step/DAC clamping! TEC/Bias closed-loop algorithms require anti-windup step limits (HMaxStep/CMaxStep) and DAC output saturation bounds (MinDAC/MaxDAC) to prevent thermal shock, wavelength drift, and laser burnout.",
                            'action': 'ADD_PID_CLAMPING',
                            'suggested_fix': "Add incremental step limits ('Result = HMaxStep/CMaxStep') and DAC range clamping ('MinDAC/MaxDAC') before DAC output."
                        })

                # Rule 10: ADC Calibration Integer Promotion & Saturation
                if re.search(r'\bcalimon[su]val\b', fname_lower) or (('cali' in fname_lower or 'slope' in fname_lower) and re.search(r'\*\s*s?slope\b', func_text, re.IGNORECASE)):
                    has_prom = any(k in func_text for k in ['int32_t', 'uint32_t', 'long', 'int64_t', 'lADCVal', 'wdADCVal'])
                    has_clamp = any(k in func_text for k in ['INT16_MAX', 'INT16_MIN', 'UINT16_MAX', '32767', '-32768', '65535'])
                    if not (has_prom and has_clamp):
                        issues.append({
                            'rule_id': 'EMBEDDED_CALI_INTEGER_PROMOTION_AND_SATURATION',
                            'severity': 'CRITICAL',
                            'file': os.path.normpath(file_path),
                            'line': func_start_line,
                            'target': current_func_name,
                            'message': f"ADC slope calibration in '{current_func_name}()' lacks 32-bit integer promotion or saturation clamping! Fixed-point multiplication of 16-bit operands without int32 promotion causes arithmetic overflow; missing saturation clamping causes dangerous sign wrapping.",
                            'action': 'ADD_CALI_SATURATION',
                            'suggested_fix': "Promote intermediate product to 'int32_t' / 'uint32_t', shift '>> 8', and clamp with INT16_MAX/INT16_MIN or UINT16_MAX before return."
                        })

                # Rule 11: Temperature LUT Hysteresis Deadband Filtering
                if 'lut_comp' in fname_lower or 'look_up_table' in fname_lower:
                    has_clamp = any(k in func_text for k in ['< 0', '< 0x', '> 0x', '> 120', '< -', 'temp <', 'temp >'])
                    has_hyst = any(k in func_text for k in ['lutidx', 'wold', 'lo', 'hi', 'abs', 'diff', 'hysteresis', 'deadband'])
                    if not (has_clamp and has_hyst):
                        issues.append({
                            'rule_id': 'EMBEDDED_LUT_MISSING_HYSTERESIS',
                            'severity': 'WARNING',
                            'file': os.path.normpath(file_path),
                            'line': func_start_line,
                            'target': current_func_name,
                            'message': f"Dynamic temperature LUT compensation in '{current_func_name}()' lacks input range clamping or hysteresis deadband! Temperature ADC jitter around boundary points causes rapid DAC oscillation, deteriorating PAM4 eye quality and TDECQ.",
                            'action': 'ADD_LUT_HYSTERESIS',
                            'suggested_fix': "Enforce temperature input clamping and add a deadband threshold (e.g. +/- 3 deg C) before triggering new LUT indexing."
                        })

                # Rule 12: Bootloader Jump Dual Interlock Authentication
                if ('mcu_startboot' in func_text or 'jump_to_boot' in func_text or 'enter_boot' in func_text) and current_func_name not in ['mcu_startboot', 'jump_to_boot']:
                    has_psw = any(k in func_text for k in ['Psw_Mod', 'PSW_MOD_BOOT', 'PSW_MOD_VEN2', 'password'])
                    has_key = any(k in func_text for k in ['BankSel', '0xFA', '0x55AA', 'magic', 'MagicKey'])
                    if not (has_psw and has_key):
                        boot_line = func_start_line
                        for l_idx, fl in enumerate(current_func_lines):
                            if any(k in fl for k in ['mcu_startboot', 'jump_to_boot', 'enter_boot']):
                                boot_line = func_start_line + l_idx
                                break
                        issues.append({
                            'rule_id': 'EMBEDDED_BOOT_JUMP_SINGLE_LOCK_HAZARD',
                            'severity': 'BLOCKER',
                            'file': os.path.normpath(file_path),
                            'line': boot_line,
                            'target': current_func_name,
                            'message': f"Bootloader jump trigger in '{current_func_name}()' lacks dual independent authentication locks! In-field firmware upgrade (IAP) jump must require both password state unlock AND a secondary magic register token (e.g. BankSel == 0xFA) to prevent accidental link dropouts.",
                            'action': 'REQUIRE_DUAL_BOOT_INTERLOCK',
                            'suggested_fix': "Require dual check: 'if ((psTab80->Psw_Mod == PSW_MOD_BOOT) && (psDDMTab->BankSel == 0xFA)) { ... }'."
                        })

                # Rule 13: Flash Erase/Write I2C Slave Isolation
                if any(k in func_text for k in ['FlashSectorErase', 'FlashWriteWords', 'FlashWrite32', 'mcu_flash_erase', 'mcu_flash_program']) and current_func_name not in ['FlashSectorErase', 'FlashWriteWords', 'FlashWrite32', 'mcu_flash_erase', 'mcu_flash_program']:
                    if 'FlashLib.c' not in file_path:
                        has_iso = any(k in func_text for k in ['mcu_i2cs_en', 'NVIC_DisableIRQ', 'I2C_Cmd', '__disable_irq'])
                        if not has_iso:
                            flash_line = func_start_line
                            for l_idx, fl in enumerate(current_func_lines):
                                if any(k in fl for k in ['FlashSectorErase', 'FlashWriteWords', 'FlashWrite32', 'mcu_flash_erase', 'mcu_flash_program']):
                                    flash_line = func_start_line + l_idx
                                    break
                            issues.append({
                                'rule_id': 'EMBEDDED_FLASH_WRITE_I2C_ISOLATION',
                                'severity': 'BLOCKER',
                                'file': os.path.normpath(file_path),
                                'line': flash_line,
                                'target': current_func_name,
                                'message': f"Flash erase/program operations in '{current_func_name}()' occur without isolating I2C slave peripheral! Flash operations stall MCU execution for tens of milliseconds; failure to disable I2C causes host Clock Stretch timeout and bus lockup.",
                                'action': 'ISOLATE_FLASH_FROM_I2C',
                                'suggested_fix': "Disable I2C slave before Flash erase/write: 'mcu_i2cs_en(0);' and re-enable after: 'mcu_i2cs_en(1);'."
                            })

                # Rule 14: Torn-Read Prevention via I2C Busy Guard
                is_isr = any(k in fname_lower for k in ['isr', 'handler', 'i2cs', 'rdc', 'irq']) or in_i2c_context or in_rdc_context
                if not is_isr and ('SffLow[' in func_text or 'SffT11[' in func_text or 'UpdtIntL()' in func_text):
                    if ('for ' in func_text or 'while ' in func_text or 'UpdtIntL' in func_text) and ('|=' in func_text or 'UpdtIntL' in func_text):
                        busy_funcs = bindings.get('busy_guard_funcs', ['wait_i2c_busy'])
                        has_busy = any(k in func_text for k in ['wait_i2c_busy', 'i2c_busy', 'i2c_wait', 'wait_i2c_free'] + list(busy_funcs))
                        if not has_busy:
                            busy_line = func_start_line
                            for l_idx, fl in enumerate(current_func_lines):
                                if any(k in fl for k in ['SffLow[', 'SffT11[', 'UpdtIntL']):
                                    busy_line = func_start_line + l_idx
                                    break
                            issues.append({
                                'rule_id': 'CMIS_I2C_BUSY_GUARD_REQUIRED',
                                'severity': 'CRITICAL',
                                'file': os.path.normpath(file_path),
                                'line': busy_line,
                                'target': current_func_name,
                                'message': f"Shared MSA shadow registers or interrupt status updated in '{current_func_name}()' without I2C busy guard! Background updates concurrent with host I2C access cause torn reads or corrupted telemetry values.",
                                'action': 'ADD_I2C_BUSY_GUARD',
                                'suggested_fix': "Add 'wait_i2c_busy();' before modifying shared MSA buffers or updating IntL."
                            })

                current_func_name = ""
                func_brace_depth = 0
                func_body_opened = False
                current_func_lines = []
                in_i2c_context = False
                in_rdc_context = False

        if current_func_name:
            current_func_lines.append(clean_line)

        # Track sliding window of recent lines for context
        recent_lines.append(clean_line)
        if len(recent_lines) > 10:
            recent_lines.pop(0)

        if not clean_line or clean_line.startswith('#'):
            # Rule 8: Low Power OR logic in macros
            if clean_line.startswith('#define') and ('G_LPwrS_R' in clean_line or 'bsp_lpmode' in clean_line):
                has_hw = any(k in clean_line for k in ['IO_LPWR', 'HwLPwr', 'Pin_LPMode'])
                has_sw = any(k in clean_line for k in ['SwLoPwr', 'Software_LowPwr', 'Reg_LowPwr'])
                if (has_hw and not has_sw) or (has_sw and not has_hw):
                    issues.append({
                        'rule_id': 'CMIS_LPMODE_OR_LOGIC_DEFECT',
                        'severity': 'CRITICAL',
                        'file': os.path.normpath(file_path),
                        'line': line_no,
                        'target': 'LowPwr',
                        'message': "Low power evaluation macro lacks dual-mode OR logic! CMIS Section 5 requires LowPwr state to evaluate BOTH the physical LPMode pin and the software SwLoPwr register bit.",
                        'action': 'FIX_LPMODE_LOGIC',
                        'suggested_fix': "Use '(psDDMTab->ModCtrls.SwLoPwr || (psDDMTab->ModCtrls.HwLPwrEn && IO_LPWR_IN()))'."
                    })
            continue

        # ----------------------------------------------------------------------
        # Rule 1: [BLOCKER] CMIS 16-bit DDM Telemetry Big-Endian Swap Check
        # ----------------------------------------------------------------------
        m = ddm_assign_pattern.search(clean_line)
        if m:
            target_expr = m.group(1)
            field_name = m.group(2)
            rhs_expr = m.group(3).strip()

            if telemetry_field_pattern.search(field_name):
                has_swap = any(re.search(r'\b' + re.escape(sig) + r'\s*\(', rhs_expr) for sig in swap_macros)
                has_shift = ('>> 8' in rhs_expr and '& 0x' in rhs_expr)

                if not (has_swap or has_shift):
                    issues.append({
                        'rule_id': 'CMIS_MISSING_ENDIAN_SWAP',
                        'severity': 'BLOCKER',
                        'file': os.path.normpath(file_path),
                        'line': line_no,
                        'target': target_expr,
                        'rhs': rhs_expr,
                        'pref_swap': pref_swap,
                        'message': f"Assignment to CMIS DDM telemetry field '{target_expr}' lacks Big-Endian byte swap! CMIS requires network byte order (MSB first); writing raw Little-Endian values corrupts switch telemetry readings.",
                        'action': 'WRAP_ENDIAN_SWAP',
                        'suggested_fix': f"Wrap RHS in '{pref_swap}(...)': '{target_expr} = {pref_swap}({rhs_expr});'"
                    })

        # ----------------------------------------------------------------------
        # Rule 2: [BLOCKER] I2C Slave ISR Long Latency Operations
        # ----------------------------------------------------------------------
        if in_i2c_context:
            for forbidden in forbidden_in_isr:
                if re.search(r'\b' + re.escape(forbidden) + r'\b', clean_line, re.IGNORECASE):
                    if 'FlashBurn' not in clean_line and 'STOP' not in clean_line:
                        issues.append({
                            'rule_id': 'CMIS_I2C_ISR_LONG_LATENCY',
                            'severity': 'BLOCKER',
                            'file': os.path.normpath(file_path),
                            'line': line_no,
                            'target': forbidden,
                            'message': f"Call to forbidden/slow operation '{forbidden}()' detected inside I2C slave context '{current_func_name}'. CMIS specifies strict clock stretch limits (<= 500us); blocking operations in ISR cause host I2C timeouts!",
                            'action': 'DEFER_I2C_OPERATION',
                            'suggested_fix': f"Move '{forbidden}()' execution to the main background task loop, or trigger only after I2C STOP condition."
                        })

        # ----------------------------------------------------------------------
        # Rule 3: [CRITICAL] CMIS Latched Flag Direct Overwrite Hazard
        # ----------------------------------------------------------------------
        if not in_rdc_context:
            m_cor = flag_ptr_pattern.search(clean_line) or buf_flag_pattern.search(clean_line)
            if m_cor:
                target_expr = m_cor.group(1)
                rhs_expr = m_cor.group(2).strip()
                issues.append({
                    'rule_id': 'CMIS_COR_OVERWRITE_HAZARD',
                    'severity': 'CRITICAL',
                    'file': os.path.normpath(file_path),
                    'line': line_no,
                    'target': target_expr,
                    'rhs': rhs_expr,
                    'message': f"Direct assignment ('=') to latched flag register '{target_expr}' outside Clear-on-Read handler! CMIS / SFF-8636 latched flags must accumulate transient alarms via bitwise OR ('|='); direct assignment overwrites and drops historical transient alarms.",
                    'action': 'CONVERT_TO_BITWISE_OR',
                    'suggested_fix': f"Change assignment '=' to bitwise OR '|=': '{target_expr} |= {rhs_expr};'"
                })

        # ----------------------------------------------------------------------
        # Rule 4: [BLOCKER] Page 00h EEPROM Unlocked Direct Write Protection
        # ----------------------------------------------------------------------
        m_p00 = re.search(r'\b(SffT00|psIDInfo->[A-Za-z0-9_]+)(?:\[[^\]]*\])?\s*(?<![|<>=!&+-])=\s*(?![=])([^;]+);', clean_line)
        if m_p00:
            target_expr = m_p00.group(1)
            in_psw_gate = any('Psw_Mod' in l or 'PSW_MOD' in l or 'password' in l.lower() or 'unlock' in l.lower() for l in recent_lines)
            if not in_psw_gate:
                issues.append({
                    'rule_id': 'CMIS_PAGE00_UNLOCKED_WRITE',
                    'severity': 'BLOCKER',
                    'file': os.path.normpath(file_path),
                    'line': line_no,
                    'target': target_expr,
                    'message': f"Direct write to Page 00h factory EEPROM ('{target_expr}') without password/unlock verification! Page 00h contains critical factory Vendor ID and calibration data; unauthorized writes corrupt EEPROM and cause switch port verification failure.",
                    'action': 'GUARD_PASSWORD_CHECK',
                    'suggested_fix': "Guard write with password check: 'if (psTab80->Psw_Mod > PSW_MOD_USR1) { ... }'."
                })

        # ----------------------------------------------------------------------
        # Rule 5: [CRITICAL] Page Select Unchecked Bounds
        # ----------------------------------------------------------------------
        if any('_adr == 127' in l or '_adr == 0x7F' in l for l in recent_lines):
            m_bounds = re.search(r'\b(SffLow\[(?:_adr|127)\]|psDDMTab->TabSel)\s*(?<![|<>=!&+-])=\s*(?![=])([^;]+);', clean_line)
            if m_bounds:
                rhs = m_bounds.group(2).strip()
                if rhs in ['_rdat', 'rdat', 'val', 'dat']:
                    has_range_check = any(('<=' in l or '>=' in l or '0x04' in l or '0x10' in l or 'sanitize' in l) for l in recent_lines)
                    if not has_range_check:
                        issues.append({
                            'rule_id': 'CMIS_PAGE_UNCHECKED_BOUNDS',
                            'severity': 'CRITICAL',
                            'file': os.path.normpath(file_path),
                            'line': line_no,
                            'target': m_bounds.group(1),
                            'message': f"Unchecked page select write ('{m_bounds.group(1)} = {rhs}') at Byte 127! Writing unvalidated page numbers causes wild memory dereferences or crashes during upper page switch; must sanitize invalid page numbers to default (0x00).",
                            'action': 'SANITIZE_PAGE_BOUNDS',
                            'suggested_fix': "Sanitize to 0x00 default: 'SffLow[_adr] = 0x00; if ((_rdat <= 0x04) || (_rdat >= 0x10 && _rdat <= 0x14)) SffLow[_adr] = _rdat;'."
                        })

    return issues


def scan_workspace(workspace_dir, changed_scope=None, include_legacy=False, force_profile=False):
    """Scan workspace for CMIS protocol violations."""
    parent_rules, child_profile = get_effective_rules(workspace_dir, force_profile)

    workspace = Path(workspace_dir).resolve()
    c_files = []
    for root, _, files in os.walk(workspace):
        if any(skip in root.lower() for skip in ['.git', 'node_modules', '.gemini', 'build']):
            continue
        for f in files:
            if f.endswith(('.c', '.h')):
                c_files.append(os.path.join(root, f))

    all_issues = []
    for file_path in c_files:
        issues = audit_cmis_in_file(file_path, parent_rules, child_profile)
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
        'child_profile': child_profile,
        'all_issues_count': len(all_issues),
        'new_blockers': new_blockers,
        'new_critical': new_critical,
        'legacy_suppressed': legacy_suppressed,
        'legacy_included': legacy_included
    }


def generate_reports(scan_results, gate_verdict, workspace_dir, output_dir=None):
    """Produce reports/report_cmis.md and reports/report_cmis.json."""
    if output_dir:
        out_path = Path(output_dir).resolve()
    else:
        out_path = Path(workspace_dir).resolve() / 'reports'
    out_path.mkdir(parents=True, exist_ok=True)

    md_file = out_path / 'report_cmis.md'
    json_file = out_path / 'report_cmis.json'
    profile = scan_results.get('child_profile', {})
    bindings = profile.get('bindings', {})

    # 1. Generate JSON report
    ai_heals = []
    for item in scan_results['new_blockers'] + scan_results['new_critical']:
        rel_path = os.path.relpath(item['file'], workspace_dir).replace('\\', '/')
        ai_heals.append({
            'rule_id': item['rule_id'],
            'file': rel_path,
            'full_path': item['file'].replace('\\', '/'),
            'line': item['line'],
            'target': item.get('target', ''),
            'message': item['message'],
            'action': item['action'],
            'pref_swap': item.get('pref_swap', 'SwapU16'),
            'instruction': f"Line {item['line']} in {rel_path}: {item['suggested_fix']}"
        })

    json_payload = {
        'gate': gate_verdict,
        'cmis_profile': {
            'project_name': profile.get('project_name'),
            'optical_spec': profile.get('optical_spec'),
            'preferred_swap': bindings.get('preferred_swap_macro'),
            'ddm_pointers': bindings.get('ddm_table_pointers'),
            'i2c_handlers': bindings.get('i2c_slave_handlers'),
            'rdc_handlers': bindings.get('rdc_handlers'),
            'intl_updaters': bindings.get('intl_updaters'),
            'latched_buffers': bindings.get('latched_flag_buffers'),
            'id_table_pointers': bindings.get('id_table_pointers'),
            'page00_buffers': bindings.get('page00_buffers'),
            'page_select_vars': bindings.get('page_select_vars'),
            'tx_disable_symbols': bindings.get('tx_disable_symbols'),
            'lpmode_symbols': bindings.get('lpmode_symbols'),
            'cdb_symbols': bindings.get('cdb_symbols'),
            'busy_guard_funcs': bindings.get('busy_guard_funcs'),
            'flash_isolation_funcs': bindings.get('flash_isolation_funcs'),
            'pid_calc_funcs': bindings.get('pid_calc_funcs'),
            'cali_funcs': bindings.get('cali_funcs'),
            'lut_comp_funcs': bindings.get('lut_comp_funcs'),
            'boot_jump_funcs': bindings.get('boot_jump_funcs')
        },
        'summary': {
            'total_cmis_violations_flagged': scan_results['all_issues_count'],
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
        "# 📡 光模块 CMIS / MSA 全域协议审查报告 (Full-Domain CMIS Gate)",
        "",
        f"> [!{'CAUTION' if gate_verdict['verdict'] == 'BLOCKED' else 'NOTE'}]",
        f"> **{gate_verdict['summary']}**",
        "",
        "## 1. 工程与协议自适应剖析概览 (Profile Summary - 11大核心规范与量产鲁棒性覆盖)",
        f"- **目标工程**: `{profile.get('project_name', 'Unknown')}`",
        f"- **检测协议族**: `{profile.get('optical_spec', 'QSFP-DD CMIS')}`",
        f"- **1. 大小端翻转首选宏**: **`{bindings.get('preferred_swap_macro', 'SwapU16')}`**",
        f"- **2. I2C 中枢与从机中断**: `{', '.join(bindings.get('i2c_slave_handlers', []))}`",
        f"- **3. 读清 (COR) 与中断联动**: `{', '.join(bindings.get('rdc_handlers', []))}` ➜ `{', '.join(bindings.get('intl_updaters', []))}`",
        f"- **4. Page 00h 出厂只读区与表头**: `{', '.join(bindings.get('page00_buffers', []))}` (`{', '.join(bindings.get('id_table_pointers', []))}`)",
        f"- **5. 分页切换与边界防呆**: `{', '.join(bindings.get('page_select_vars', []))}`",
        f"- **6. 激光安全与 TxDisable 互锁**: `{', '.join(bindings.get('tx_disable_symbols', []))}`",
        f"- **7. 模块/通道低功耗评估**: `{', '.join(bindings.get('lpmode_symbols', []))}`",
        f"- **8. CDB 固件升级交互符号**: `{', '.join(bindings.get('cdb_symbols', []))}`",
        f"- **9. I2C 撕裂读保护 (Busy Guard)**: `{', '.join(bindings.get('busy_guard_funcs', []))}`",
        f"- **10. Flash 擦写脱扣隔离 (Isolation)**: `{', '.join(bindings.get('flash_isolation_funcs', []))}`",
        f"- **11. 温控 PID 积分抗饱和与限幅**: `{', '.join(bindings.get('pid_calc_funcs', []))}`",
        f"- **12. 模拟量校准提升与饱和防溢出**: `{', '.join(bindings.get('cali_funcs', []))}`",
        f"- **13. 查表温补迟滞防抖 (Hysteresis)**: `{', '.join(bindings.get('lut_comp_funcs', []))}`",
        f"- **14. 升级跳转双重鉴权 (Dual Lock)**: `{', '.join(bindings.get('boot_jump_funcs', []))}`",
        f"- **门禁判定结果**: **`{gate_verdict['verdict']}`** (Exit code: `{gate_verdict['exit_code']}`)",
        f"- **模式**: `{gate_verdict['mode']}`",
        f"- **🚨 新增阻断级违规 (Blockers)**: `{len(scan_results['new_blockers'])}` 处",
        f"- **🛡️ 老代码历史问题静默 (Legacy Suppressed)**: `{len(scan_results['legacy_suppressed'])}` 处",
        ""
    ]

    active_issues = scan_results['new_blockers'] + scan_results['new_critical']
    if scan_results['legacy_included']:
        active_issues = active_issues + scan_results['legacy_included']

    if active_issues:
        md_lines.extend([
            "## 2. 🚨 光模块 CMIS 协议违规清单 (Protocol Violations)",
            "> [!CAUTION]",
            "> 以下违规若合入固件，会导致交换机读取光模块温度/光功率彻底错乱，或引发 I2C Clock Stretch 超时导致链路中断！",
            "",
            "| 源码文件与行号 | 违规目标 | 规则分类 | 危害与修复方案 |",
            "| :--- | :---: | :---: | :--- |"
        ])
        for iss in active_issues:
            rel_path = os.path.relpath(iss['file'], workspace_dir).replace('\\', '/')
            md_lines.append(
                f"| [`{rel_path}:{iss['line']}`](file:///{iss['file'].replace('\\', '/')}#L{iss['line']}) | "
                f"`{iss.get('target', '')}` | **{iss['rule_id']}** | {iss['suggested_fix']} |"
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
    parser = argparse.ArgumentParser(description="Optical Module CMIS Protocol Analyzer")
    parser.add_argument('--workspace', required=True, help="Path to firmware workspace")
    parser.add_argument('--changed-files', nargs='*', default=None, help="Specific files changed by AI")
    parser.add_argument('--diff', nargs='?', const='HEAD', default=None, help="Git diff reference")
    parser.add_argument('--profile', action='store_true', help="Force re-generation of cmis_project_profile.json")
    parser.add_argument('--include-legacy', action='store_true', help="Include historical legacy issues in report")
    parser.add_argument('--gate', action='store_true', default=True, help="Enable gate mode exit codes")
    parser.add_argument('--output-dir', default=None, help="Directory to store reports")
    parser.add_argument('--no-save', action='store_true', help="Do not save reports to disk")
    args = parser.parse_args()

    changed_scope = resolve_changed_scope(args.workspace, args.changed_files, args.diff)
    scan_results = scan_workspace(args.workspace, changed_scope, args.include_legacy, force_profile=args.profile)

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

