---
name: embedded-firmware-analyzer
description: >-
  Deep embedded C/C++ firmware analysis engine combining cppcheck (static code safety analysis),
  pyelftools, and mapfile-parser (joint ELF + MAP binary layout and memory budget profiling).
  Automatically activates when inspecting embedded MCU projects (ARM Cortex-M0/M3/M4/M7/M23/M33,
  RISC-V, STM32, ADuCM, NXP, TI, ESP32, Keil MDK, EIDE, IAR, GCC), reviewing firmware memory footprint
  (Flash, SRAM, IRAM/TCM, stack/heap), diagnosing HardFaults, uninitialized variables, null pointers,
  buffer overflows, or auditing symbol cross-references.
license: MIT
metadata:
  version: "1.0.0"
---

# Embedded Firmware & MCU Joint Analyzer (Cppcheck + ELF + MAP)

This skill equips Antigravity with specialized domain intelligence for **Embedded C/C++ Firmware Engineering**. It bridges the gap between source code static verification and compiled binary reality by jointly running **`cppcheck`** (for deterministic bug detection) alongside **`pyelftools`** and **`mapfile-parser`** (for precision memory budgeting, subsystem footprint decomposition, and symbol cross-referencing).

---

## 1. When to Use This Skill

Activate this skill whenever:
- Working in an embedded C/C++ firmware codebase (containing `.c`, `.h`, `.cpp`, `.s`, `.map`, `.elf`, `.axf`, or `.uvprojx`/`eide.json`).
- The user asks to:
  - "分析当前嵌入式工程" / "分析固件内存" / "查看代码质量"
  - "优化 Flash / RAM 占用" / "哪些函数或变量占内存最多？"
  - "这个大数组/变量在什么地方被谁用了？" (e.g. symbol tracing)
  - "排查 HardFault / 死机 / 随机重启 / 内存越界风险"
  - "运行静态代码检查" / "用 cppcheck 检查代码"
- Reviewing Git diffs or refactoring MCU drivers, memory allocators, or interrupt routines.

---

## 2. Standalone Tool Suite Architecture

The skill provides 9 focused, independent command-line analyzers and 1 auto-healer engine located in:
`<skill_dir>/scripts/`

| 独立分析脚本 | 专注领域 | 核心技术引擎 | 输出重点 |
| :--- | :--- | :--- | :--- |
| **`cppcheck_analyzer.py`** | 静态代码安全审计 | `cppcheck` XML v2 | 未初始化变量、空指针、越界、严格别名 |
| **`mem_budget_analyzer.py`**| 物理内存与符号分布 | `pyelftools` + `mapfile-parser` | Flash/SRAM 精确预算、Top 符号、子系统归因、符号反查 |
| **`struct_analyzer.py`** | 结构体空洞与对齐优化 | `pyelftools.dwarf` | 逐字节内存布局、Padding 空洞、4-2-1 重排 C 补丁 |
| **`stack_analyzer.py`** | 最大调用栈与栈溢出风险 | GCC `.su` + DAG / Keil `.htm` | 最深调用链、中断嵌套推演、单级大局部变量告警 |
| **`complexity_analyzer.py`**| 圈复杂度与认知负载 | `lizard` AST 引擎 | 状态机分支复杂度、Bug 庇护所、超长单体函数、重构建议 |
| **`concurrency_analyzer.py`**| 中断并发与原子性审计 | ISR-to-Task 符号交叉回溯 | `[BLOCKER]` 跨中断共享缺少 volatile、`[CRITICAL]` 多字节撕裂缺临界区保护 |
| **`polling_timeout_analyzer.py`**| 硬件外设死等与防死锁 | 循环条件 AST / 硬件寄存器识别 | `[CRITICAL]` 硬件标志位裸等死循环、缺少超时计数器与看门狗 |
| **`float_bloat_analyzer.py`**| 软浮点与双精度膨胀审计 | 正则/词法 AST | `[BLOCKER]` 显式 double 禁用、`[CRITICAL]` 浮点常量漏加 f、64位数学函数 |
| **`cmis_protocol_analyzer.py`**| 光模块 CMIS / MSA 协议专属审查 | 父子继承配置 + 语义绑定 | 详见 [CMIS 规范手册](rules/CMIS_RULES_SPECIFICATION.md)：17大规范覆盖 DDM 大端 Swap、I2C 延展、只读区、PID 双重限幅、Flash 脱扣隔离、升级双重鉴权等 |
| **`embedded_ocr_heal.py`** | 一键闭环自愈引擎 | 精确 AST / 字符级补丁器 | 类似 OCR `heal_code`，读取 JSON 自动打补丁，支持 `--dry-run` 与 `--retest` |

```mermaid
flowchart TD
    subgraph 独立质检工具矩阵 (9 Standalone Analyzers)
        T1["cppcheck_analyzer.py<br>(静态缺陷审计)"]
        T2["mem_budget_analyzer.py<br>(内存预算 & 符号)"]
        T3["struct_analyzer.py<br>(结构体对齐 & 空洞)"]
        T4["stack_analyzer.py<br>(最大栈深 & 调用链)"]
        T5["complexity_analyzer.py<br>(圈复杂度 & 认知负载)"]
        T6["concurrency_analyzer.py<br>(中断并发 & 原子性)"]
        T7["polling_timeout_analyzer.py<br>(硬件死等超时)"]
        T8["float_bloat_analyzer.py<br>(软浮点与双精度膨胀)"]
        T9["cmis_protocol_analyzer.py<br>(光模块 CMIS 协议专属)"]
    end
    
    A[固件工程 / Workspace] --> T1 & T2 & T3 & T4 & T5 & T6 & T7 & T8 & T9
    T1 & T2 & T3 & T4 & T5 & T6 & T7 & T8 & T9 --> GATE["embedded_ocr_gate.py<br>(全域统一门禁调度)"]
    GATE --> R_MD["report_ocr_gate.md<br>(人类总决断书)"]
    GATE --> R_JSON["report_ocr_gate.json<br>(AI 机器自愈清单)"]
    R_JSON --> HEAL["embedded_ocr_heal.py<br>(一键闭环自愈引擎)"]
    HEAL -->|"--retest 验证"| GATE
```

### Unified Embedded OCR Quality Gate (AI-Native Governance)

The suite provides a unified quality gate entry point **`embedded_ocr_gate.py`** specifically designed to govern AI-generated code, enforce hardware safety limits, and suppress legacy codebase noise:
- **`--gate` (Default)**: Enforces hard exit code (`0` = PASSED, `1` = BLOCKED, `2` = ARCHITECTURAL_HAZARD).
- **`--changed-files <files>` / `--diff [ref]`**: Isolates review to touched scope. Legacy code defects outside the touched scope are automatically marked as `legacy_suppressed` and will NOT block merging.
- **`--include-legacy` (Optional switch)**: Include and report all historical legacy technical debt in the generated reports (by default, legacy code is silenced to avoid noise).
- **`ai_heal_instructions`**: Machine-readable JSON tasks with explicit instructions and C patches for AI self-healing.

```bash
# Run incremental quality gate (legacy code silenced by default)
python scripts/embedded_ocr_gate.py --workspace "<workspace_dir>" --changed-files "bsp_msa.c"

# Run incremental quality gate AND include legacy debt overview in report
python scripts/embedded_ocr_gate.py --workspace "<workspace_dir>" --changed-files "bsp_msa.c" --include-legacy
```

### Dual Default Output Architecture (AI + Human)

By default, every tool in this suite automatically produces **two synchronized reports** saved into the `reports/` folder:
1. **`report_<name>.md` (For Humans)**: Rich Markdown report featuring Markdown tables, alert callouts, call graph trees, and clean formatting for review in IDEs or Git diffs.
2. **`report_<name>.json` (For AI / Automation)**: Fully structured, machine-readable JSON containing raw metrics, line-number mappings, and AST/DWARF symbols for AI context consumption and automated CI/CD pipelines.

| 脚本工具 | 默认 Markdown 报告 (Human) | 默认 JSON 报告 (AI) |
| :--- | :--- | :--- |
| **`embedded_ocr_gate.py`** | `reports/report_ocr_gate.md` | `reports/report_ocr_gate.json` |
| `cppcheck_analyzer.py` | `reports/report_cppcheck.md` | `reports/report_cppcheck.json` |
| `mem_budget_analyzer.py` | `reports/report_memory.md` | `reports/report_memory.json` |
| `struct_analyzer.py` | `reports/report_structs.md` | `reports/report_structs.json` |
| `stack_analyzer.py` | `reports/report_stack.md` | `reports/report_stack.json` |
| `complexity_analyzer.py` | `reports/report_complexity.md` | `reports/report_complexity.json` |
| `concurrency_analyzer.py` | `reports/report_concurrency.md` | `reports/report_concurrency.json` |
| `polling_timeout_analyzer.py` | `reports/report_timeout.md` | `reports/report_timeout.json` |
| `float_bloat_analyzer.py` | `reports/report_float.md` | `reports/report_float.json` |
| `cmis_protocol_analyzer.py` | `reports/report_cmis.md` | `reports/report_cmis.json` |

*Note: All tools support `--output-dir <dir>` to redirect output, `-o <path>` to customize name, `--no-save` to skip disk writes, and `--format [markdown|json]` to control console stdout.*

### Isolated Portable Environment & One-Click Distribution (独立环境与一键分发)

The entire skill is packaged to be **100% self-contained and isolated** inside `<skill_dir>/` for effortless download, sharing, and deployment:
- **Isolated Python Virtual Environment (`.venv/`)**: Keeps dependencies (`pyelftools`, `mapfile-parser`, `lizard`) strictly encapsulated without polluting the global host Python.
- **Bundled Portable Tools (`tools/cppcheck/`)**: Contains standalone Windows binary (`cppcheck.exe`, DLLs, `cfg/`, `platforms/`), eliminating external installation dependencies.
- **One-Click Setup Scripts**:
  - Windows: `setup_env.bat` (automatically creates `.venv` and installs `requirements.txt`)
  - Linux/macOS: `setup_env.sh`
- **One-Click Wrappers**:
  - `run_gate.bat --workspace "<path>"`: Automatically uses the isolated `.venv` python to run the unified 9-dimension gate.
  - `run_heal.bat --workspace "<path>"`: Automatically runs the AI auto-healer inside `.venv`.

### CLI Command Reference

Each tool can be executed independently according to the task at hand:

#### 1. 统一 AI 代码质检门禁 (`embedded_ocr_gate.py`)
```bash
# Incremental scan against modified files (Exit 0 on pass, 1 on AI blocker)
python scripts/embedded_ocr_gate.py --workspace "<workspace_dir>" --changed-files "bsp_msa.c"
```

#### 2. 静态代码缺陷审计 (`cppcheck_analyzer.py`)
```bash
# Incremental scan with gate enforcement
python scripts/cppcheck_analyzer.py --workspace "<workspace_dir>" --changed-files "bsp_msa.c" --gate
```

#### 3. 物理内存预算与符号分布 (`mem_budget_analyzer.py`)
```bash
# Auto-detects ELF and MAP in workspace (generates reports/report_memory.md & .json)
python scripts/mem_budget_analyzer.py --workspace "<workspace_dir>" --gate
```

#### 4. 结构体内存对齐与空洞审计 (`struct_analyzer.py`)
```bash
# Incremental struct audit (only flags structs in touched files)
python scripts/struct_analyzer.py --workspace "<workspace_dir>" --changed-files "spica_rules.h" --gate
```

#### 5. 最大调用栈与栈溢出安全审计 (`stack_analyzer.py`)
```bash
# Incremental stack audit (only flags functions in touched files exceeding 128B)
python scripts/stack_analyzer.py --workspace "<workspace_dir>" --changed-files "mcu.c" --gate
```

#### 6. 代码圈复杂度与认知负载分析 (`complexity_analyzer.py`)
```bash
# Incremental complexity audit (only flags functions in touched files with CCN > 15)
python scripts/complexity_analyzer.py --workspace "<workspace_dir>" --changed-files "bsp_msa.c" --gate
```

#### 7. 中断并发与原子性强行注入 (`concurrency_analyzer.py`)
```bash
# Incremental concurrency audit (flags missing volatile in ISR and non-atomic multi-byte accesses)
python scripts/concurrency_analyzer.py --workspace "<workspace_dir>" --changed-files "code/app/main.c" --gate
```

#### 8. 硬件外设死等与防死锁超时审计 (`polling_timeout_analyzer.py`)
```bash
# Incremental polling timeout audit (flags bare while loops polling hardware without timeout guards)
python scripts/polling_timeout_analyzer.py --workspace "<workspace_dir>" --changed-files "code/_HAL_MCU/mcu.c" --gate
```

#### 9. 软浮点与双精度膨胀隐患审计 (`float_bloat_analyzer.py`)
```bash
# Incremental float bloat audit (flags double keywords, missing 'f' suffix, and double math calls)
python scripts/float_bloat_analyzer.py --workspace "<workspace_dir>" --changed-files "Drivers/UrtLib.c" --gate
```

#### 10. 光模块 CMIS / MSA 协议专属审查 (`cmis_protocol_analyzer.py`)
```bash
# Auto-generate child profile for new optical transceiver project
python scripts/cmis_protocol_analyzer.py --workspace "<workspace_dir>" --profile

# Incremental CMIS audit (flags missing Big-Endian SwapU16 on DDM fields & I2C ISR blocking operations)
python scripts/cmis_protocol_analyzer.py --workspace "<workspace_dir>" --changed-files "bsp_msa.c" --gate
```

#### 11. 一键闭环自愈修复引擎 (`embedded_ocr_heal.py`)
```bash
# Safe preview of surgical patches (Dry-Run mode, no files touched)
python scripts/embedded_ocr_heal.py --workspace "<workspace_dir>"

# Apply patches with automatic .bak backups and re-test OCR gate
python scripts/embedded_ocr_heal.py --workspace "<workspace_dir>" --apply --retest
```

---

## 3. Standard 4-Phase Embedded Analysis Workflow

When conducting a comprehensive embedded analysis, follow these 4 steps:

### Phase 1: Hardware & Memory Budget Audit
Using `pyelftools` on `.elf`:
- **Flash (ROM) Allocation**:
  - Code segment (`.text`, `.ramcode` LMA).
  - Read-Only data (`.rodata`, vector tables `__Vectors`, string literals).
  - Initialized data LMA (`.data` load copy stored in Flash).
- **SRAM Allocation**:
  - RW initialized data (`.data` runtime VMA).
  - Zero-initialized uninitialized data (`.bss`).
  - Heap & Stack reservations (e.g. `_user_heap_stack`, `Stack_Size`).
- **Specialized Memory Regions**:
  - Instruction RAM / TCM / CCMRAM (e.g., ADuCM `0x10000000`, STM32 `0x10000000`).
- **Headroom Evaluation**:
  - Calculate RAM margin: If `(Data + BSS + Stack) / SRAM_Capacity > 85%`, flag critical risk of stack smashing / collision.

### Phase 2: Translation Unit & Subsystem Decomposition
Using `mapfile-parser` on `.map`:
- Decompose code and data footprint by functional subsystem:
  - **Application**: MSA, Protocol stack, Business logic.
  - **BSP**: Board-level drivers, pin multiplexing, PMIC.
  - **DSP / Math Core**: Algorithms, filter coefficients, lookup tables.
  - **HAL & Peripherals**: I2C, SPI, UART, Timer, DMA.
  - **CMSIS & RTOS**: Startup vector, context switch, scheduler.
  - **C Runtime Library**: `libc`, `libm`, IEEE754 emulation routines.
- Identify top bloat files (e.g., oversized `.o` modules).

### Phase 3: Static Reliability & HardFault Defect Audit
Using `cppcheck` with XML v2 output:
- Prioritize **Critical Reliability Hazards**:
  - `uninitvar`: Uninitialized stack variable before read (causes non-deterministic MCU behavior or jumps to garbage addresses).
  - `nullPointer` / `nullPointerArithmetic`: Null pointer dereference triggering HardFault.
  - `arrayIndexOutOfBounds` / `bufferAccessOutOfBounds`: Buffer overflows overwriting adjacent global variables or corrupting the return address on the stack.
  - `objectIndex`: Taking pointer of local scalar and accessing non-zero index.
- Audit **Embedded Portability & Alignment Hazards**:
  - `invalidPointerCast`: Casting between incompatible pointer types (e.g., `unsigned int*` to `float*`), violating strict aliasing.
  - Pointer alignment: Casting `uint8_t*` buffer to `uint32_t*` struct on Cortex-M0/M0+ can trigger an unaligned `LDR` UsageFault.
  - Shift overflow: `shiftTooManyBits` or signed left-shifts corrupting bitmask registers.

### Phase 4: Remediation & Precision Optimization
- For oversized functions in Flash:
  - Review inlining policy (excessive `inline` or `__attribute__((always_inline))`).
  - Check for duplicated lookup tables that should be marked `const` (moving them from RAM to Flash).
- For oversized variables in RAM:
  - Investigate if static buffers can be reduced or shared with unions.
  - Verify alignment attributes (e.g. `__attribute__((aligned(4)))` for DMA transfers).
- For static analysis bugs:
  - Provide immediate, syntactically correct code patches to initialize variables and guard pointer dereferences.

---

## 4. MCU Hardware Safety Checklist (Agent Mental Model)

When reviewing embedded code or diagnosing crashes, always verify against these embedded-specific realities:

| Potential Hazard | Root Cause in MCU Architecture | Recommended Action / Mitigation |
| :--- | :--- | :--- |
| **Unaligned Memory Access** | Cortex-M0/M0+ does not support unaligned 32-bit `LDR`/`STR`. Cortex-M3/M4/M7 supports it only on normal memory, but unaligned access to Device/Peripheral memory (`0x40000000+`) always triggers `HardFault`. | Use `sys_memcpy` or `__attribute__((packed, aligned(1)))` for network/protocol packet parsing. |
| **Stack Overflow Collision** | In ARM Cortex-M, the MSP stack grows downward toward `.bss` and `.data`. High local array allocations cause silent memory corruption. | Move large arrays (`> 128 Bytes`) out of function stack frames into dedicated static buffers or heap. |
| **Missing `volatile` in ISR** | Compiler optimizes register polling loops into infinite loops if variables modified in interrupts lack `volatile`. | Declare shared ISR flags and peripheral hardware registers as `volatile`. |
| **DMA Buffer Placement** | DMA controllers frequently cannot access certain memory regions (e.g. Core-Coupled Memory / ITCM), and require 4-byte or cache-line alignment. | Verify linker scatter file / section attributes (`__attribute__((section(".dma_ram")))`). |
| **FPU / Float Emulation Bloat** | Using double precision `double` literals (e.g. `1.0` instead of `1.0f`) on single-precision FPUs pulls in software emulation routines (`__ieee754_log`, `__aeabi_dmul`), ballooning Flash. | Audit floating-point constants and cast to single-precision `float`. |

---

## 5. Report Quality Standards

Whenever presenting an analysis report to the user:
1. **Always lead with the Memory Budget Table**: Show Flash and SRAM totals, utilized KB, and remaining headroom.
2. **Highlight Actionable Findings**: Do not drown the user in harmless style warnings; elevate true bugs (`uninitvar`, `nullPointer`, `arrayIndexOutOfBounds`) with exact file and line numbers.
3. **Connect Symbols to Code**: When discussing a symbol (like `TabBuf` or `spica_cp_rules_to_overlays`), explain its purpose, memory section, and originating `.c` file.
4. **Deliver Ready-to-Apply Diffs**: When bugs are detected, provide the exact code modification needed to fix them.

