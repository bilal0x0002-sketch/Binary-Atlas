# Binary Atlas - PE Malware Analysis Engine

> **Educational Static Analysis Tool for Windows PE Executables** — Learning & Research Only

![Python](https://img.shields.io/badge/python-3.8+-blue)
![Status](https://img.shields.io/badge/status-UNDER%20DEVELOPMENT-orange)
![License](https://img.shields.io/badge/license-MIT-gray)
![Platform](https://img.shields.io/badge/platform-Windows-blue)

---
---

## 📋 Table of Contents

1. [What Is Binary Atlas?](#what-is-binary-atlas)
2. [Project Status & Limitations](#project-status--limitations)
3. [Architecture Overview](#architecture-overview)
4. [Detection Modules (14 Engines)](#detection-modules-14-engines)
5. [How It Works](#how-it-works)
6. [Project Structure](#project-structure)
7. [Installation & Setup](#installation--setup)
8. [Usage Guide](#usage-guide)
9. [Configuration System](#configuration-system)
10. [Output & Reports](#output--reports)
11. [False Positive Issues](#false-positive-issues)
12. [Development Roadmap](#development-roadmap)
13. [Contributing](#contributing)
14. [FAQ](#faq)

---

## What Is Binary Atlas?

Binary Atlas is an **educational static PE (Portable Executable) analysis engine** that demonstrates how to detect suspicious characteristics in Windows binaries without executing them. It combines 14 independent detection modules to analyze PE files for malware indicators.

### Key Concept: Static Analysis

Analyzes PE file structures, imports, and patterns **without running code**:

```
Analysis Characteristics:
✓ Safe         — No code execution
✓ Repeatable   — Identical results every run
✓ Transparent  — Evidence-based findings
✓ Offline      — No internet/external dependencies

✗ Limited      — Can't see runtime behavior
✗ Pattern-based — High false positive potential
✗ No execution — Misses dynamic tricks
✗ Heuristic    — Confidence-based, not definitive
```

---

## Project Status & Limitations

### Current Status: UNDER DEVELOPMENT

| PE Parsing | ✅ Working |
| Detectors (14) | 🟡 Needs refinement |
| Report Generation | ✅ Working |
| YARA Scanning | 🟡 Rules need improvement |

### Known Limitations

#### 1. **High False Positive Rate**
Stateless pattern matching without behavioral context

#### 2. **No Execution Context**
Can't distinguish between legitimate and malicious API usage

#### 3. **Limited YARA Rule Quality**
Broad rules cause false positives on legitimate software

#### 4. **Independent Detectors**
14 modules work separately without cross-validation

#### 5. **No Behavioral Verification**
API/string presence ≠ actual execution or usage

#### 6. **Missing Features**
No machine learning, cloud integration, or sandboxing

#### 7. **Incomplete Testing**
No comprehensive test suite or edge case coverage

### What This Tool IS Good For

✅ Learning PE file internals and static analysis fundamentals
✅ Research on malware detection techniques  
✅ Building and testing detection modules
✅ Prototyping security tools in controlled environments
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
└─ Returns findings with evidence

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
---
```
## Project Structure
```
---
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
│   └── yara_rules/                           # 35+ Rules
│       ├── behavioral_detection.yar
│       ├── hardcoded_c2.yar
│       ├── malware_families.yar
│       └── [more...]
│
├── output/                                   # Generated reports
└── results/                                  # Previous results
---

---
```
## Installation & Setup

### Requirements

- **Python** 3.8+
- **pefile** ≥2023.2.7
- **pyyaml** ≥6.0
- **rich** ≥13.0.0
- **yara-python** ≥4.2.0

### Installation

```bash
git clone https://github.com/bilal0x0002-sketch/binary-atlas.git
cd binary-atlas
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py --help
```

---

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

---

## Configuration System

Binary Atlas uses **22 Python configuration files** to control behavior.

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

---

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

---

## Output Examples

### PE Headers & Optional Headers
![PE Headers](./example%20images/Pe%20headers%20optional%20headers.png)

### File Identification & Execution Context
![File Identification](./example%20images/File%20Identification%20and%20privilleges%20ande%20xecution%20context.png)

### Section Analysis
![Section Analysis](./example%20images/section%20analysis.png)

### Section Analysis Console Output
![Section Output](./example%20images/section%20analysis%20console%20output%20example.png)

### Timestamps & Security Flags
![Timestamps](./example%20images/time%20stamps%2C%20security%20flag.png)

### Imported DLL Functions
![Imports](./example%20images/imported%20dll%20func.png)

### Anti-Analysis & Persistence Detection
![Anti-Analysis](./example%20images/anti%20analysis%20persistence.png)

### Overlay Analysis
![Overlay](./example%20images/Overlay%20analysis.png)

### Example Analysis Output
![Example Output](./example%20images/example%20output.png)

---

## Development Roadmap

**In Progress:** Unified scoring, false positive reduction, YARA improvements

**Not Planned:** Sandboxing, network monitoring

## Contributing

Welcome contributions: bug fixes, rule improvements, documentation

## FAQ

**Q: Can I use this in production?**  
A: NO. Educational software only.

**Q: Can it execute or sandbox files?**  
A: No. Static analysis only—no code execution.

**Q: Why so many false positives?**  
A: Pattern matching without behavioral context. Professional tools are heavily tuned; this demonstrates detection challenges.

**Q: What if results disagree with my antivirus?**  
A: Trust the antivirus. Professional tools are verified by expert teams, (even professional tools can sometime false flag).

**Q: Can it analyze packed binaries?**  
A: Detects packing but cannot unpack automatically. Packed content analysis is limited.

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

*Last Updated: April 17, 2026 | Status: Under Active Development | NOT Production Ready*
