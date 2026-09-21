#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Embedded Open Code Review (OCR) Common Utilities
Provides incremental Git Diff parsing, changed-scope resolution,
legacy technical debt suppression, and AI auto-heal instruction contracts.
"""

import os
import sys
import subprocess
from pathlib import Path


def resolve_changed_scope(workspace_dir, changed_files=None, diff_ref=None, include_legacy=False):
    """
    Resolve which files and lines are considered 'touched by AI / current changes'.
    Returns:
        dict: {
            "is_incremental": bool,
            "include_legacy": bool,
            "touched_files": set of normalized relative or absolute paths,
            "touched_lines": dict of norm_path -> set(line numbers) (empty set means whole file touched)
        }
    """
    workspace = Path(workspace_dir).resolve()
    touched_files = set()
    touched_lines = {}

    # 1. Explicitly passed changed files
    if changed_files is not None:
        for f in changed_files:
            p = Path(f)
            if not p.is_absolute():
                p = (workspace / p).resolve()
            norm = str(p).replace('\\', '/').lower()
            touched_files.add(norm)
            touched_lines[norm] = set()  # Whole file touched
        return {
            "is_incremental": True,
            "include_legacy": include_legacy,
            "touched_files": touched_files,
            "touched_lines": touched_lines,
            "mode": "EXPLICIT_FILES"
        }

    # 2. Check if git repository is available
    git_dir = None
    curr = workspace
    while curr != curr.parent:
        if (curr / ".git").exists():
            git_dir = curr
            break
        curr = curr.parent

    if git_dir and (diff_ref or diff_ref is None):
        try:
            # Check if inside git worktree
            check_cmd = ["git", "-C", str(git_dir), "rev-parse", "--is-inside-work-tree"]
            res = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0 and res.stdout.strip() == "true":
                # Get diff
                diff_cmd = ["git", "-C", str(git_dir), "diff", "-U0"]
                if diff_ref:
                    diff_cmd.append(diff_ref)
                diff_proc = subprocess.run(diff_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
                
                if diff_proc.returncode == 0 and diff_proc.stdout.strip():
                    current_file = None
                    for line in diff_proc.stdout.splitlines():
                        if line.startswith("+++ b/"):
                            rel_path = line[6:].strip()
                            abs_p = (git_dir / rel_path).resolve()
                            current_file = str(abs_p).replace('\\', '/').lower()
                            touched_files.add(current_file)
                            if current_file not in touched_lines:
                                touched_lines[current_file] = set()
                        elif line.startswith("@@ ") and current_file:
                            # Parse @@ -old,count +new,count @@
                            parts = line.split("@@")
                            if len(parts) >= 2:
                                hunk_info = parts[1].strip()
                                for token in hunk_info.split():
                                    if token.startswith("+"):
                                        range_str = token[1:]
                                        if "," in range_str:
                                            start, count = map(int, range_str.split(","))
                                        else:
                                            start = int(range_str)
                                            count = 1
                                        for ln in range(start, start + count):
                                            touched_lines[current_file].add(ln)
                                            
                    # Also check untracked files
                    status_proc = subprocess.run(
                        ["git", "-C", str(git_dir), "status", "--porcelain"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace"
                    )
                    if status_proc.returncode == 0:
                        for s_line in status_proc.stdout.splitlines():
                            if s_line.startswith("?? "):
                                untracked_file = s_line[3:].strip()
                                abs_untracked = (git_dir / untracked_file).resolve()
                                norm = str(abs_untracked).replace('\\', '/').lower()
                                touched_files.add(norm)
                                touched_lines[norm] = set()

                    if touched_files:
                        return {
                            "is_incremental": True,
                            "include_legacy": include_legacy,
                            "touched_files": touched_files,
                            "touched_lines": touched_lines,
                            "mode": "GIT_DIFF"
                        }
        except Exception:
            pass

    # 3. Fallback: Full repository scan (not incremental)
    return {
        "is_incremental": False,
        "include_legacy": True,
        "touched_files": set(),
        "touched_lines": {},
        "mode": "FULL_SCAN"
    }


def is_file_or_line_touched(file_path, line_no, scope):
    """Check whether a finding at file_path:line_no falls inside the touched scope."""
    if not scope.get("is_incremental"):
        return True  # Full scan considers everything touched
        
    if not file_path:
        return False
        
    norm_f = str(Path(file_path).resolve()).replace('\\', '/').lower()
    
    # Check if exact file or basename is in touched_files
    matched_file = None
    if norm_f in scope["touched_files"]:
        matched_file = norm_f
    else:
        # Match by relative suffix or basename
        for tf in scope["touched_files"]:
            if norm_f.endswith(tf) or tf.endswith(norm_f) or Path(tf).name == Path(norm_f).name:
                matched_file = tf
                break
                
    if not matched_file:
        return False
        
    lines = scope["touched_lines"].get(matched_file, set())
    if not lines:
        # Whole file is touched
        return True
        
    # If specific lines tracked, check if line_no is touched
    if line_no is not None and line_no > 0:
        return line_no in lines
        
    return True


def build_gate_verdict(new_blockers, critical_issues, legacy_issues, arch_hazards, scope):
    """
    Compute unified Quality Gate verdict and exit code.
    Exit codes:
      0 = PASSED (No blocking defects in new code, legacy code suppressed)
      1 = BLOCKED (AI/new code introduced BLOCKER or CRITICAL defects, must self-heal)
      2 = ARCHITECTURAL_HAZARD (Legacy architectural failure like global SRAM/Stack collision)
    """
    blocker_count = len(new_blockers)
    critical_count = len(critical_issues)
    arch_count = len(arch_hazards)
    legacy_count = len(legacy_issues)
    include_legacy = scope.get("include_legacy", False)
    
    if arch_count > 0:
        verdict = "ARCHITECTURAL_HAZARD"
        exit_code = 2
        summary_msg = f"Triggered {arch_count} architectural performance/memory hazard(s) requiring architectural review."
    elif blocker_count > 0 or critical_count > 0:
        verdict = "BLOCKED"
        exit_code = 1
        summary_msg = f"Blocked: {blocker_count} blocker(s) and {critical_count} critical issue(s) detected in newly modified code."
    else:
        verdict = "PASSED"
        exit_code = 0
        if include_legacy:
            summary_msg = f"Passed: Incremental changes are clean. (Included {legacy_count} legacy technical debt findings in report)."
        else:
            summary_msg = f"Passed: Clean incremental changes. Automatically suppressed {legacy_count} legacy technical debt findings."
        
    return {
        "verdict": verdict,
        "exit_code": exit_code,
        "is_incremental": scope.get("is_incremental", False),
        "include_legacy": include_legacy,
        "mode": scope.get("mode", "FULL_SCAN"),
        "summary": summary_msg,
        "stats": {
            "new_blockers": blocker_count,
            "new_critical": critical_count,
            "arch_hazards": arch_count,
            "legacy_suppressed": 0 if include_legacy else legacy_count,
            "legacy_included": legacy_count if include_legacy else 0
        }
    }


def format_ai_heal_instruction(rule_id, file, line, message, action, instruction, patch=None):
    """Format structured AI auto-heal prompt."""
    res = {
        "rule_id": rule_id,
        "file": os.path.basename(file) if file else "Unknown",
        "full_path": str(file).replace('\\', '/') if file else "",
        "line": line or 0,
        "message": message,
        "action": action,
        "instruction": instruction
    }
    if patch:
        res["suggested_patch"] = patch
    return res

