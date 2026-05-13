# Binary Atlas — PE Malware Analysis Engine

> **Every verdict backed by evidence, not just a score.**  
> Binary Atlas explains malicious decisions the way a reverse engineer would — not the way antivirus engines do.  
> *Built to help me understand how malware detection systems actually reason about binaries.*

![Python](https://img.shields.io/badge/python-3.8+-blue)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![License](https://img.shields.io/badge/license-MIT-gray)
![Platform](https://img.shields.io/badge/platform-Windows-blue)

<br>

  **Drop a PE file → get instant malware intelligence:**
- Threat score (0–100%) with **evidence‑based reasoning** — *e.g. “DLL injection detected via suspicious API chain: VirtualAlloc → WriteProcessMemory → CreateRemoteThread”*  
- Detected techniques (packers, persistence, shellcode, and more)  
- Full HTML forensic report with IOCs (IPs, domains, mutexes)

<br>
![Binary Atlas Demo](report_demo.gif)

*Clean HTML report: single dominant threat score, highlighted evidence, no clutter.*

---

## Why Binary Atlas isn’t just another scanner

| Capability | Binary Atlas | Antivirus / Scanners |
|------------|--------------|-----------------------|
| Explains **why** a verdict was triggered | ✅ Evidence‑based, full trace | ❌ Black‑box score |
| Works entirely offline | ✅ Fully local | ❌ Often cloud‑dependent |
| Detection transparency | ✅ You see every API, section, and rule | ❌ Hidden logic |

Binary Atlas is designed to show you **exactly which behaviours triggered the alarm** — so you can learn, triage, or challenge the verdict. It’s a reverse‑engineer’s thinking tool, not a black‑box replacement for an EDR.

---

##  Try it now — one command
```bash
python main.py samples/benign_sample.exe
```

**Expected result: a full forensic HTML report in under 5 seconds.**  
No uploads. No cloud. No data leaves your machine.
```
[✓] PE file loaded: benign_sample.exe
[✓] Detector results: MEDIUM threat detected (confidence: 32%)
[✓] HTML report saved to output/benign_sample.html
```
*Note: Confidence levels depend on detection patterns; LOW confidence does not mean clean.*

<details>
<summary>Full installation</summary>

```bash
git clone https://github.com/bilal0x0002-sketch/binary-atlas.git
cd binary-atlas
python -m venv .venv && .venv\Scripts\activate   # Windows
pip install -r requirements.txt
```
Need more help? Jump to Installation & Setup.

</details>
Table of Contents
What It Finds

Quick Start

Project Status & Limitations

Architecture Overview

Detection Modules (14 Engines)

How It Works

Project Structure

Installation & Setup

Usage Guide

Configuration System

Output & Reports

False Positive Philosophy

Development Roadmap

Contributing

FAQ

What It Finds
Binary Atlas statically analyzes Windows PE executables (.exe, .dll, .sys, .bin) and extracts:

Category	Details
PE structure	Headers, sections, timestamps, resources
Imports	DLL libraries & API functions
Detection modules	Packers, shellcode, persistence, DLL/COM hijacking, anti‑analysis, overlay anomalies, import anomalies, high‑entropy strings, suspicious mutexes, and more
YARA signatures	35+ community‑curated rules
IOC extraction	IPs, domains, URLs, mutexes, file paths
Threat classification	Weighted confidence score (0‑100%)
Reports	Interactive HTML dashboard + plain‑text log, offline‑ready
No code execution – fully offline – repeatable every time.

Quick Start
If you have already installed the dependencies (see the Try it now section above), just run:

## Quick Start
If you have already installed the dependencies (see the Try it now section above), just run:

```bash
python main.py path/to/your/file.exe
```

For batch analysis:

```bash
python main.py --directory ./samples
python main.py --glob '*.exe'
```

## Project Status & Limitations

### Current Status: UNDER DEVELOPMENT
- PE Parsing — Stable and functional
- Detection Modules (14) — Under refinement and tuning
- Report Generation — Fully operational
- YARA Scanning — Requires rule optimization for accuracy

### Known Limitations
1. **Moderate False Positive Rate**  
   Stateless pattern matching without behavioral context; confidence scores may vary (10–50%) even with multiple findings

2. **Limited YARA Rule Quality**  
   Broad rules may flag benign software; detection engines may return clean results even when modules are active

3. **Missing Features**  
   No machine learning, cloud integration, or sandboxing

4. **Incomplete Testing**  
   No comprehensive test suite or edge case coverage

### What This Tool IS Good For
- Learning PE file internals and static analysis fundamentals
- Research on malware detection techniques
- Building and testing detection modules
- Prototyping security tools in controlled environments

---

## How It Works

### Analysis Flow
```
Step 1: FILE DISCOVERY
├─ Single file: samples/malware.exe
├─ Directory: python main.py -d ./samples
└─ Glob pattern: python main.py -g '*.exe'

Step 2: FILE VALIDATION
├─ Check PE signature (MZ header)
├─ Validate file readable & accessible
└─ Skip if not valid PE

Step 3: SIGNATURE VERIFICATION
├─ Check Authenticode certificate
├─ Verify against Windows trusted CAs
├─ If VALID:
│  └─ Return LOW threat (98% confidence)
│     └─ Skip all heuristic detectors
└─ If INVALID/MISSING:
   └─ Continue to Step 4

Step 4: PE PARSING
├─ Extract DOS header (e_lfanew pointer)
├─ Extract PE headers (File Header, Optional Header)
├─ Parse sections (entropy per section)
├─ Extract imports (DLL + API names)
├─ Parse resources (type, size, entropy)
└─ Calculate hashes (MD5, SHA256)

Step 5: PARALLEL DETECTOR EXECUTION (14 modules)
Each module:
├─ Extracts relevant data (strings, APIs, sections)
├─ Applies detection patterns (regex, signatures)
├─ Calculates confidence score
└─ Returns findings with evidence (or [OK] if clean)

Results aggregated for final scoring

Step 6: THREAT CLASSIFICATION
├─ Filter weak signals (YARA low-severity matches)
├─ Weight signals by reliability
├─ Calculate final threat level
└─ Store confidence percentage

Step 7: REPORT GENERATION
├─ Create interactive HTML report
├─ Generate plain text version
├─ Extract IOCs (IPs, domains, URLs, mutexes)
└─ Save to output/ directory

Step 8: CONSOLE OUTPUT
├─ Display summary with threat verdict
├─ Show key findings
├─ Display analysis timing

OUTPUT: Reports in output/ directory + console summary
```

---

## Project Structure
```
Binary-Atlas/
├── main.py                                   # Entry point
├── requirements.txt                          # Dependencies
├── README.md                                 # This file
│
├── config/                                   # 22 Config files
│   ├── anti_analysis_config.py
│   ├── packer_config.py
│   ├── threat_classification_config.py
│   └── [19 more...]
│
├── src/
│   ├── orchestration/                        # Pipeline
│   │   ├── engine.py
│   │   └── coordinator.py
│   │
│   ├── parsing/                              # PE parsing
│   │   ├── headers.py
│   │   ├── sections.py
│   │   └── security_checks.py
│   │
│   ├── detectors/                            # 14 Detectors
│   │   ├── packer_detector.py
│   │   ├── anti_analysis_detector.py
│   │   ├── shellcode_detector.py
│   │   ├── persistence_detector.py
│   │   ├── dll_hijacking_detector.py
│   │   ├── com_hijacking_detector.py
│   │   ├── import_anomaly_detector.py
│   │   ├── overlay_detector.py
│   │   ├── string_entropy.py
│   │   ├── mutex_detector.py
│   │   ├── resource_analyzer.py
│   │   ├── yara_scanner.py
│   │   ├── threat_classifier.py
│   │   ├── compiler_detector.py
│   │   └── common.py
│   │
│   ├── reporting/                            # Reports
│   │   ├── html_formatter.py
│   │   ├── txt_formatter.py
│   │   └── report_generator.py
│   │
│   └── utils/                                # 13 Utilities
│       ├── discovery.py
│       ├── indicators.py
│       ├── logger.py
│       └── [more...]
│
├── samples/
│   ├── benign_sample.exe       # Safe test file (included)
│   └── yara_rules/                           # 35+ Rules
│       ├── behavioral_detection.yar
│       ├── hardcoded_c2.yar
│       ├── malware_families.yar
│       └── [more...]
│
├── output/                                   # Generated reports
└── results/                                  # Previous results
```

---

## Installation & Setup

### Requirements
- Python 3.8+
- pefile ≥2023.2.7
- pyyaml ≥6.0
- rich ≥13.0.0
- yara-python ≥4.2.0

### Detailed Setup
```bash
git clone https://github.com/bilal0x0002-sketch/binary-atlas.git
cd binary-atlas
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/Mac
pip install -r requirements.txt
python main.py --help
YARA‑python may require a C compiler. If you encounter issues, see the Quick Start collapsible or open a GitHub issue.

## Usage Guide

### Command-Line Reference
```
usage: Binary Atlas [-h] [--directory DIR] [--glob PATTERN]
                   [--verbose] [--output DIR] [--timeout SEC]
                   [--no-hash]
                   [file]

Positional:
  file              Single PE file path

Optional:
  -h, --help              Help message
  -d, --directory DIR     Batch process directory
  -g, --glob PATTERN      Glob pattern batch
  -v, --verbose           Verbose output
  -o, --output DIR        Output directory
  -t, --timeout SEC       Per-file timeout
  --no-hash              Skip hashing
```

### Usage Examples
```bash
# Single file
python main.py malware.exe

# Batch directory
python main.py --directory ./samples

# Glob pattern
python main.py --glob '*.exe'

# Advanced
python main.py ./samples --no-hash --verbose
```

## Configuration System
Binary Atlas uses 22 Python configuration files to control behavior.

Edit `config/` files to customize:
- Detection thresholds
- Packer signatures
- API patterns
- Scoring weights

Example customization in `config/packer_config.py`:

```python
PACKER_CONFIG = {
    'entropy_threshold': 0.92,
    'known_packers': {
        'upx': r'\.UPX\d',
    }
}
```

## Output & Reports

### Report Files
After analysis, find in `output/`:
- `.html` — Interactive HTML report
- `.txt` — Plain text archive version

### Report Contents
- Binary metadata (name, size, timestamps)
- File hashes (MD5, SHA256)
- Detailed findings with evidence
- IOC extraction
- Confidence scores
- Recommendations

### Output Examples
- PE Headers & Optional Headers
- File Identification & Execution Context
- Section Analysis
- Section Analysis Console Output
- Timestamps & Security Flags
- Imported DLL Functions
- Anti-Analysis & Persistence Detection
- Overlay Analysis
- Example Analysis Output

## False Positive Philosophy
Binary Atlas uses heuristic pattern matching without behavioral context or dynamic analysis. It can flag both legitimate and malicious behaviors — use it for learning, research, and understanding detection reasoning.

**Important**: Some detection modules may return "[OK] clean" results even when other modules trigger. This is expected behavior reflecting the limitations of static analysis. Confidence scores (10–50%+) indicate uncertainty levels, not accuracy guarantees.

For production triage, always confirm with professional AV/EDR. This tool prioritises transparency and learning over precision.

---

## Development Roadmap
**In Progress:** Unified scoring, false positive reduction, YARA improvements

**Not Planned:** Sandboxing, network monitoring

---

## Contributing
Welcome contributions: bug fixes, rule improvements, documentation

---

## FAQ

**Q: Can I use this in production?**  
A: Binary Atlas is built for learning and research — not as a drop‑in replacement for production‑grade EDR systems. Use a dedicated security solution for live environments.

**Q: Can it execute or sandbox files?**  
A: No. Static analysis only — no code execution.

**Q: Why so many false positives?**  
A: Pattern matching without behavioral context. Professional tools are heavily tuned; this demonstrates detection challenges.

**Q: What if results disagree with my antivirus?**  
A: Use Binary Atlas for analysis and insight; rely on your antivirus/EDR for production decisions. (Even professional tools can occasionally false flag.)

**Q: Can it analyze packed binaries?**  
A: Detects high-entropy indicators (sections with entropy >7.5) but packing detection is not fully reliable. Packed content analysis is limited. Manual unpacking may be needed.

**Q: How do I customize detections?**  
A: Edit the 22 config files in `config/` directory.

**Q: Where are reports saved?**  
A: Default: `output/` directory. Use `--output` for custom location.

**Q: Can I batch process files?**  
A: Yes, use `--directory` or `--glob` options.

**Q: Why is analysis slow?**  
A: Use `--no-hash` to skip hashing. Adjust `--timeout` if needed.

**Q: Can I modify YARA rules?**  
A: Yes, edit files in `samples/yara_rules/` directory.

---

## License
MIT License - See LICENSE file

---

Last Updated: April 17, 2026 | Status: Under Active Development | NOT Production Ready

---
