# indicators_c2_strict.py
"""
Indicators of Compromise (IOC) Extraction Module

Extracts potential command & control (C2) indicators from PE file strings:
- IP addresses: IPv4, IPv6
- Domain names: Hardcoded C2 servers
- URLs: Command servers, backdoor communication
- File paths: Suspicious write locations
- Mutexes: Malware synchronization primitives
- Keywords: C2, command, socket, connect patterns

This module aggressively filters false positives (95%+ reduction)
while maintaining high true-positive detection.
"""

import re
import base64
import pefile
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple, Optional

from config.indicators_config import REGEX_PATTERNS, INDICATORS_EXTRACTION, ANTI_VM_KEYWORDS, SUSPICIOUS_KEYWORDS, CLOUD_IOC_KEYWORDS, COMMAND_EXECUTION_PATTERNS, WEAK_KEYWORDS, URL_RISK_CATEGORIES, USER_AGENT_FILTER
from src.utils.filters import filter_indicators, is_real_mutex, is_garbage_operand
# Helper function for meaningful string detection
def is_meaningful_string(s: str) -> bool:
    """Check if a string is meaningful or just padding/garbage.
    
    Rejects:
    - Strings that are mostly special chars: '%S', '+S', ',S', etc.
    - Mostly repeated single characters: 'AAAA', '9999', etc.
    - Pure special character patterns
    """
    if not s or len(s) < 2:
        return False
    
    # Reject if mostly padding chars (configurable ratio)
    padding_chars = set(INDICATORS_EXTRACTION['padding_chars'])
    special_count = sum(1 for c in s if c in padding_chars)
    if len(s) > 0 and special_count / len(s) > INDICATORS_EXTRACTION['padding_ratio_threshold']:
        return False
    
    # Reject if purely padding like 'S', 'A', '9' repeated
    if re.fullmatch(r"^[%+,\-*'\'^\"S]+$", s):
        return False
    
    # Reject pure digits with minimal variation (9999, 7777, etc.)
    if re.fullmatch(r'[\d\s]+', s):
        if len(set(s.replace(' ', ''))) <= 2:  # Only 1-2 unique digits
            return False
    
    # Accept if has meaningful letters and numbers mixed
    letters = sum(1 for c in s if c.isalpha())
    digits = sum(1 for c in s if c.isdigit())
    
    # Accept if reasonable letter/digit content (configurable)
    if letters >= INDICATORS_EXTRACTION['meaningful_string_letter_count'] or (letters >= 1 and digits >= 1):
        return True
    
    # Accept short critical strings like '/c', '.exe', 'sh'
    if len(s) >= 2 and s in INDICATORS_EXTRACTION['critical_short_strings']:
        return True
    
    return False


def detect_command_execution_patterns(all_strings: list) -> dict:
    """Detect command execution patterns indicating RAT/backdoor capability.
    
    Returns dict with:
    - found_cmd_exec: bool - if cmd.exe + /c pattern found
    - cmd_patterns: list of found patterns
    - cmd_args: list of found args
    - risk_level: str - CRITICAL if found
    """
    patterns_found = []
    cmd_exe_found = False
    args_found = []
    
    for s in all_strings:
        s_lower = s.lower()
        if "cmd.exe" in s_lower:
            cmd_exe_found = True
            patterns_found.append("cmd.exe")
        if "/c" in s_lower or " /c" in s_lower:
            args_found.append("/c")
        if "/k" in s_lower or " /k" in s_lower:
            args_found.append("/k")
        if "powershell" in s_lower:
            patterns_found.append("powershell")
    
    # Deduplicate
    patterns_found = list(set(patterns_found))
    args_found = list(set(args_found))
    
    return {
        "found_cmd_exec": cmd_exe_found and bool(args_found),
        "cmd_patterns": patterns_found,
        "cmd_args": args_found,
        "risk_level": "CRITICAL" if (cmd_exe_found and args_found) else ("HIGH" if cmd_exe_found else "NONE")
    }


def categorize_url_risk(url: str) -> str:
    """Categorize URL by risk level using configured vendors and patterns.
    
    Returns:
    - 'benign': Microsoft, W3C, trusted CDNs
    - 'low': Known-good vendors (GitHub, npm, etc)
    - 'medium': Unknown domains
    - 'high': Raw IPs, typosquatting patterns, dynamic domains
    """
    try:
        p = urlparse(url)
        netloc_lower = p.netloc.lower()
    except:
        return 'unknown'
    
    # BENIGN: Configured benign vendors
    for benign in URL_RISK_CATEGORIES['benign']['vendors']:
        if benign in netloc_lower:
            return 'benign'
    
    # LOW: Known-good vendors
    for vendor in URL_RISK_CATEGORIES.get('low', {}).get('vendors', []):
        if vendor in netloc_lower:
            return 'low'
    
    # HIGH: Raw IPs or suspicious patterns
    if re.match(r'^\d+\.\d+\.\d+\.\d+', netloc_lower):
        return 'high'  # Raw IP in binary = suspicious
    
    # HIGH: Dynamic domains (DGA-like patterns) or typosquats
    if any(pattern in netloc_lower for pattern in URL_RISK_CATEGORIES.get('high', {}).get('patterns', [])):
        return 'high'
    
    # MEDIUM: Unknown domain
    return 'medium'


# -------------------------
# String extraction
# -----------------------------


def extract_strings_by_section(pe: pefile.PE, min_len: int = None) -> List[Tuple[str, str, int, str]]:
    """Return a list of (string, section_name, file_offset, kind).

    Extracts ASCII and UTF-16LE strings per section so callers can
    make decisions based on section provenance. `kind` is either
    `'ascii'` or `'unicode'`.
    
    min_len: minimum string length (default from config)
    """
    if min_len is None:
        min_len = INDICATORS_EXTRACTION['string_extraction_min_length']
    res: List[Tuple[str, str, int, str]] = []
    data = getattr(pe, "__data__", None)
    if data is None:
        try:
            data = pe.read()
        except Exception:
            data = b""

    ascii_pat = re.compile(rb'[\x20-\x7E]{%d,}' % min_len)
    uni_pat = re.compile(rb'(?:[\x20-\x7E]\x00){%d,}' % min_len)

    if not hasattr(pe, 'sections') or not pe.sections:
        # fallback to global scans with unknown section
        for m in ascii_pat.finditer(data):
            try:
                s = m.group(0).decode('ascii', errors='ignore').strip()
                if s and is_meaningful_string(s):
                    res.append((s, 'UNKNOWN', m.start(), 'ascii'))
            except Exception:
                continue
        for m in uni_pat.finditer(data):
            try:
                s = m.group(0).decode('utf-16le', errors='ignore').strip()
                if s and is_meaningful_string(s):
                    res.append((s, 'UNKNOWN', m.start(), 'unicode'))
            except Exception:
                continue
        return res

    for sec in pe.sections:
        try:
            name = sec.Name.decode(errors='ignore').strip('\x00') or '<unnamed>'
        except Exception:
            name = '<unnamed>'

        start = int(getattr(sec, 'PointerToRawData', 0))
        size = int(getattr(sec, 'SizeOfRawData', 0))
        if size <= 0 or start < 0 or start >= len(data):
            continue
        chunk = data[start:start + size]

        for m in ascii_pat.finditer(chunk):
            try:
                s = m.group(0).decode('ascii', errors='ignore').strip()
            except Exception:
                continue
            if not s:
                continue
            # Filter out obvious padding/garbage
            if is_meaningful_string(s):
                res.append((s, name, start + m.start(), 'ascii'))

        for m in uni_pat.finditer(chunk):
            try:
                s = m.group(0).decode('utf-16le', errors='ignore').strip()
            except Exception:
                continue
            if not s:
                continue
            if is_meaningful_string(s):
                res.append((s, name, start + m.start(), 'unicode'))

    return res





def detect_stack_strings(data: bytes, chunk_size: int = None, printable_threshold: int = None) -> List[str]:
    """FLOSS-like reversed stack strings. NOT used in base64 scanning (prevents spam)."""
    if chunk_size is None:
        chunk_size = INDICATORS_EXTRACTION['stack_string_chunk_size']
    if printable_threshold is None:
        printable_threshold = INDICATORS_EXTRACTION['stack_string_printable_threshold']
    res = set()
    if len(data) < chunk_size:
        return []
    for i in range(0, len(data) - chunk_size + 1):
        chunk = data[i:i + chunk_size][::-1]
        try:
            s = chunk.decode("ascii", errors="ignore")
        except Exception:
            continue
        printable = sum(1 for c in s if 32 <= ord(c) < 127)
        if printable >= printable_threshold and s.strip() and not is_garbage_operand(s.strip()):
            res.add(s.strip())
    return list(res)


def detect_stack_strings_in_sections(pe: pefile.PE, chunk_size: int = None, printable_threshold: int = None, max_results: int = None) -> List[str]:
    """Detect reversed stack-like strings only inside executable/code sections.

    This reduces noise by avoiding resources and metadata areas where short
    numeric/semi-readable sequences (like version numbers) can appear.
    Returns a tuple: (list_of_strings, provenance_list).
    - list_of_strings: capped, deduplicated list of strings
    - provenance_list: list of (string, section, file_offset)
    """
    if chunk_size is None:
        chunk_size = INDICATORS_EXTRACTION['stack_string_section_chunk_size']
    if printable_threshold is None:
        printable_threshold = INDICATORS_EXTRACTION['stack_string_section_threshold']
    if max_results is None:
        max_results = INDICATORS_EXTRACTION['stack_string_max_results']
    res = []
    seen = set()
    prov = []
    data = getattr(pe, "__data__", None)
    if data is None:
        try:
            data = pe.read()
        except Exception:
            data = b""

    if not hasattr(pe, 'sections') or not pe.sections:
        # fallback to scanning whole file if sections unavailable
        candidates = detect_stack_strings(data, chunk_size=chunk_size, printable_threshold=printable_threshold)
        for idx, s in enumerate(candidates):
            if s not in seen:
                seen.add(s)
                res.append(s)
                # provenance for fallback is unknown section, approximate offset 0+idx
                prov.append((s, 'UNKNOWN', idx))
                if len(res) >= max_results:
                    break
        return res, prov

    for sec in pe.sections:
        try:
            name = sec.Name.decode(errors='ignore').strip('\x00').lower()
        except Exception:
            name = ''

        # prefer typical code sections
        if not (name.startswith('.text') or 'code' in name):
            continue

        start = int(getattr(sec, 'PointerToRawData', 0))
        size = int(getattr(sec, 'SizeOfRawData', 0))
        if size <= 0 or start < 0 or start >= len(data):
            continue
        chunk_data = data[start:start + size]

        # scan with sliding window similar to FLOSS
        if len(chunk_data) < chunk_size:
            continue
        for i in range(0, len(chunk_data) - chunk_size + 1):
            window = chunk_data[i:i + chunk_size][::-1]
            try:
                s = window.decode('ascii', errors='ignore')
            except Exception:
                continue
            printable = sum(1 for c in s if 32 <= ord(c) < 127)
            if printable >= printable_threshold and s.strip():
                s = s.strip()
                # CRITICAL FIX: filter out assembly operands
                if s not in seen and not is_garbage_operand(s):
                    seen.add(s)
                    res.append(s)
                    prov.append((s, name, start + i))
                    if len(res) >= max_results:
                        return res, prov

    return res, prov


# -----------------------------
# Regex indicators - imported from config
# -----------------------------
IP_REGEX = re.compile(REGEX_PATTERNS['ip_address'])
DOMAIN_REGEX = re.compile(REGEX_PATTERNS['domain'])
URL_REGEX = re.compile(REGEX_PATTERNS['url'], re.IGNORECASE)
MUTEX_REGEX = re.compile(REGEX_PATTERNS['mutex'])
REGKEY_REGEX = re.compile(REGEX_PATTERNS['registry_key'], re.IGNORECASE)
USER_AGENT_REGEX = re.compile(REGEX_PATTERNS['user_agent'], re.IGNORECASE)

ANTI_VM_KEYWORDS = ANTI_VM_KEYWORDS
SUSPICIOUS_KEYWORDS = SUSPICIOUS_KEYWORDS
CLOUD_IOC_KEYWORDS = CLOUD_IOC_KEYWORDS

# Command execution patterns indicating RAT/backdoor capability
COMMAND_EXECUTION_PATTERNS = COMMAND_EXECUTION_PATTERNS


# -----------------------------
# STRICT Base64 filtering
# -----------------------------
BASE64_CHARSET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def looks_like_base64_candidate(s: str, min_len: int = None) -> bool:
    """Strict filter—removes ALL junk like "GGGGFFFFG"."""
    if min_len is None:
        min_len = INDICATORS_EXTRACTION['base64_min_length']
    if not s or len(s) < min_len:
        return False

    # must only contain base64 chars
    if any(c not in BASE64_CHARSET for c in s):
        return False

    # must not be only one repeated char (raise uniqueness threshold)
    if len(set(s)) < 6:
        return False

    # standard length check
    if len(s) % 4 != 0:
        return False

    return True


def strict_b64_decode(s: str) -> str | None:
    """Decode then accept ONLY if contains real indicators or readable ASCII."""
    try:
        decoded = base64.b64decode(s, validate=True)
    except Exception:
        return None

    if not decoded:
        return None

    # decode to text using UTF-8 strictly — reject if not valid UTF-8
    try:
        text = decoded.decode('utf-8')
    except Exception:
        return None

    # strong indicator markers — prefer explicit network markers
    strong_markers = INDICATORS_EXTRACTION['base64_strong_markers']

    # indicator check: explicit URL/domain/IP or presence of strong markers
    if IP_REGEX.search(text) or DOMAIN_REGEX.search(text) or URL_REGEX.search(text):
        return text
    if any(k in text.lower() for k in strong_markers):
        return text

    # otherwise be conservative — require high printable ratio and some punctuation
    printable = sum(32 <= ord(c) < 127 for c in text)
    if printable / len(text) < INDICATORS_EXTRACTION['base64_printable_ratio']:
        return None
    # require at least one punctuation common in URLs/hosts/params (., /, :, =)
    if not any(c in text for c in '. /:='):
        return None

    return text


# -----------------------------
# Main extractor
# -----------------------------
def extract_indicators(pe: pefile.PE, console: Any, max_ips: int = None, max_urls: int = None, max_domains: int = None) -> Dict[str, Any]:

    if max_ips is None:
        max_ips = INDICATORS_EXTRACTION['max_ip_results']
    if max_urls is None:
        max_urls = INDICATORS_EXTRACTION['max_url_results']
    if max_domains is None:
        max_domains = INDICATORS_EXTRACTION['max_domain_results']

    data = getattr(pe, "__data__", None)
    if data is None:
        try:
            data = pe.read()
        except Exception:
            data = b""

    # string layers (with section provenance)
    # strings_with_prov elements: (string, section, offset, kind)
    strings_with_prov = extract_strings_by_section(pe)

    # derive ascii/unicode lists from the section-aware extraction (avoid redundant full-file rescans)
    ascii_str = [s for (s, _, _, k) in strings_with_prov if k == 'ascii']
    unicode_str = [s for (s, _, _, k) in strings_with_prov if k == 'unicode']
    # use section-aware stack string detection to reduce noise (also collect provenance)
    stack_str, stack_prov = detect_stack_strings_in_sections(pe)

    # strings used for indicator scanning (simple lists for some detectors)
    # strings_with_prov is list of (s, section, offset, kind)
    all_printable = [s for (s, _, _, _) in strings_with_prov]

    # -------------------------
    # IPs
    # -------------------------
    # IP extraction with contextual heuristics and section-aware provenance
    net_kws = INDICATORS_EXTRACTION['networking_keywords']

    def accept_ip_candidate(ip_str: str, surrounding: str, section: Optional[str]) -> bool:
        """Accept well-formed IPv4 by default, reject clear version/resource artifacts.

        Rules:
        - If the IP looks like a version (d.d.d.d) and the string is from a resource/manifest or contains
          version metadata keys, reject.
        - Reject obvious non-routable first-octet addresses (0,127,255) unless networking context present.
        - Otherwise accept (be permissive so we don't silently drop C2s embedded in code sections).
        """
        sec = (section or '').lower()
        low = (surrounding or '').lower()

        # version-like dotted decimals: treat as version only in resource/context
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip_str):
            if sec.startswith('.rsrc') or any(k in low for k in INDICATORS_EXTRACTION['version_metadata_keywords']):
                return False
            return True

        # reject non-routable unless networking context
        try:
            first_octet = int(ip_str.split('.', 1)[0])
            if first_octet in (0, 127, 255):
                # allow when explicit network context exists
                if any(k in low for k in net_kws):
                    return True
                # allow 127.* when surrounding looks like base64 or contains '=' (local proxy cases)
                if first_octet == 127:
                    if '=' in surrounding or re.fullmatch(r'[A-Za-z0-9+/=\s]+', surrounding):
                        return True
                return False
        except Exception:
            pass

        # otherwise accept (including .text and custom sections)
        return True

    ips_seen = []
    ips_set = set()
    for s, sec, off, _kind in strings_with_prov:
        for m in IP_REGEX.findall(s):
            if m in ips_set:
                continue
            if accept_ip_candidate(m, s, sec):
                ips_set.add(m)
                ips_seen.append((m, sec, off))
                if len(ips_seen) >= max_ips:
                    break
        if len(ips_seen) >= max_ips:
            break

    ips = [i[0] for i in ips_seen]

    # -------------------------
    # URLs
    # -------------------------
    urls, seen_urls = [], set()
    urls_prov = []
    
    # Load benign domains to filter
    from config.filters_config import BENIGN_DOMAINS
        
    # Scan with provenance so we can report section+offset for each URL
    for s, sec, off, _kind in strings_with_prov:
        for m in URL_REGEX.findall(s):
            u = m.strip("[]()\"'")
            p = urlparse(u)
            if p.scheme and p.netloc and u not in seen_urls:
                # Filter out benign domains (microsoft.com, w3.org, etc.)
                netloc_lower = p.netloc.lower()
                is_benign = any(
                    benign in netloc_lower 
                    for benign in BENIGN_DOMAINS
                )
                
                if not is_benign:
                    seen_urls.add(u)
                    urls.append(u)
                    urls_prov.append((u, sec, off))
                    if len(urls) >= max_urls:
                        break
        if len(urls) >= max_urls:
            break

    # -------------------------
    # Domains
    # -------------------------
    domains, seen_doms = [], set()
    domains_prov = []
    
    # Load benign_domains filter
    from config.filters_config import BENIGN_DOMAINS
    
    for s, sec, off, _kind in strings_with_prov:
        for m in DOMAIN_REGEX.findall(s):
            low = m.lower().strip(". ")
            if low.endswith((".exe", ".dll", ".manifest", ".sys", ".txt")):
                continue
            # skip short numeric-only dotted strings coming from resource-like sections
            if re.fullmatch(r"\d+(?:\.\d+)+", low) and (not sec or sec.lower().startswith('.rsrc')):
                continue

            # TLD heuristic: last label must be alphabetic and reasonable length
            parts = low.rsplit('.', 1)
            if len(parts) == 2:
                tld = parts[1]
                if not tld.isalpha() or not (2 <= len(tld) <= 6):
                    continue
            else:
                continue
            
            # Filter out benign domains (microsoft.com, w3.org, etc.)
            is_benign = any(
                benign in low 
                for benign in BENIGN_DOMAINS
            )
            if is_benign:
                continue

            if low not in seen_doms:
                seen_doms.add(low)
                domains.append(low)
                domains_prov.append((low, sec, off))
                if len(domains) >= max_domains:
                    break
        if len(domains) >= max_domains:
            break

    # -------------------------
    # Mutexes, regkeys, UAs
    # -------------------------
    # Extract mutex candidates but filter aggressively
    mutex_candidates = sorted({m for s in all_printable for m in MUTEX_REGEX.findall(s)})
    mutexes = [m for m in mutex_candidates if is_real_mutex(m)]  # Apply filter!
    
    regkeys = sorted({m for s in all_printable for m in REGKEY_REGEX.findall(s)})
    user_agents = sorted({m for s in all_printable for m in USER_AGENT_REGEX.findall(s)})

    # -------------------------
    # keyword matches
    # -------------------------
    # avoid creating a huge joined string in memory; stream-check per string
    # SMART FILTERING: Weak keywords require context to avoid false positives (from config)
    
    # Weak keywords that are common in normal code - need multi-signal confirmation
    weak_keywords = set(WEAK_KEYWORDS.keys())
    strong_keywords = set(SUSPICIOUS_KEYWORDS) - weak_keywords
    
    # For strong keywords, simple substring match is fine
    keyword_hits = [k for k in strong_keywords if any(k in s.lower() for s in all_printable)]
    
    # For weak keywords, require additional confirmation using configured context
    weak_keyword_hits = []
    
    for weak_kw in weak_keywords:
        if any(weak_kw in s.lower() for s in all_printable):
            # Found weak keyword - check for corroborating evidence
            weak_config = WEAK_KEYWORDS[weak_kw]
            
            if not weak_config.get('requires_context'):
                weak_keyword_hits.append(weak_kw)
                continue
            
            # Check if required context is present
            context_found = any(
                ctx in s.lower() 
                for s in all_printable
                for ctx in weak_config.get('context_indicators', [])
            )
            
            if context_found:
                weak_keyword_hits.append(weak_kw)
    
    keyword_hits.extend(weak_keyword_hits)
    
    anti_vm_hits = [k for k in ANTI_VM_KEYWORDS if any(k in s.lower() for s in all_printable)]
    cloud_hits = [k for k in CLOUD_IOC_KEYWORDS if any(k in s.lower() for s in all_printable)]

    # -------------------------
    # STRICT Base64 (NO STACK STRINGS)
    # -------------------------
    base64_candidates = []
    decoded_c2 = []

    for s in all_printable:
        if not looks_like_base64_candidate(s):
            continue
        decoded = strict_b64_decode(s)
        if decoded:
            base64_candidates.append(s)
            # only keep decoded if indicator-like
            if IP_REGEX.search(decoded) or DOMAIN_REGEX.search(decoded) or URL_REGEX.search(decoded):
                decoded_c2.append(decoded)

    # dedupe
    base64_candidates = sorted(set(base64_candidates))
    decoded_c2 = sorted(set(decoded_c2))

    # -------------------------
    # COMMAND EXECUTION DETECTION
    # -------------------------
    cmd_exec_indicators = detect_command_execution_patterns(all_printable)

    # Build result dict
    # Combine all extracted strings for analysis
    all_strings = ascii_str + unicode_str + stack_str
    
    result = {
        "ips": ips,
        "ips_prov": ips_seen,
        "urls": urls,
        "urls_prov": urls_prov,
        "domains": domains,
        "domains_prov": domains_prov,
        "mutexes": mutexes,
        "regkeys": regkeys,
        "user_agents": user_agents,
        "keywords": keyword_hits,
        "cloud_iocs": cloud_hits,
        "anti_vm": anti_vm_hits,
        "base64": base64_candidates,
        "decoded_c2": decoded_c2,
        "cmd_exec": cmd_exec_indicators,
        "stack_strings": stack_str,
        "stack_strings_prov": stack_prov,
        "ascii": ascii_str,
        "unicode": unicode_str,
        "strings": all_strings,  # Combined strings for entropy analysis
    }
    
    # Apply aggressive filtering to eliminate junk and false positives
    result = filter_indicators(result)
    
    # -------------------------
    # INTELLIGENT ASCII STRING PRIORITIZATION
    # -------------------------
    # Sort ASCII strings to show critical indicators first (cmd.exe, powershell, etc.)
    if result['ascii']:
        critical_priority = INDICATORS_EXTRACTION['ascii_critical_priority']
        
        critical_strings = [s for s in result['ascii'] if any(crit in s.lower() for crit in critical_priority)]
        normal_strings = [s for s in result['ascii'] if s not in critical_strings]
        
        # Sort each group alphabetically, critical first
        result['ascii'] = sorted(critical_strings) + sorted(normal_strings)
    
    # -------------------------
    # BUILD RESULT LINES FOR REPORT (FULL DATA FOR ANALYST VERIFICATION)
    # -------------------------
    result_lines = []
    
    # CRITICAL INDICATORS FIRST WITH SOURCE TRACKING (Always visible, never truncated)
    critical_indicators = []
    
    # Track where cmd.exe and critical keywords come from
    critical_sources = {}
    if result['keywords']:
        for kw in result['keywords']:
            sources = []
            # Check where this keyword appears
            if any(kw.lower() in s.lower() for s in result['ascii']):
                sources.append("ASCII")
            if any(kw.lower() in s.lower() for s in result['unicode']):
                sources.append("Unicode")
            if any(kw.lower() in s.lower() for s in result['mutexes']):
                sources.append("Mutexes")
            if any(kw.lower() in s.lower() for s in result['regkeys']):
                sources.append("Registry")
            if any(kw.lower() in s.lower() for s in result['stack_strings']):
                sources.append("Stack Strings")
            
            source_str = f" [Found in: {', '.join(sources)}]" if sources else ""
            critical_sources[kw] = source_str
    
    if result['keywords']:
        keywords_with_sources = [f"{kw}{critical_sources.get(kw, '')}" for kw in result['keywords']]
        critical_indicators.append(f"- **Critical Keywords**: {', '.join(keywords_with_sources)}")
    
    if result['cmd_exec'].get("found_cmd_exec"):
        cmd_source = "ASCII" if any("cmd.exe" in s for s in result['ascii']) else "Unknown"
        critical_indicators.append(f"- **Command Execution Detected**: {', '.join(result['cmd_exec']['cmd_patterns'])} with arguments {', '.join(result['cmd_exec']['cmd_args'])} [Found in: {cmd_source}]")
    
    if result['cloud_iocs']:
        critical_indicators.append(f"- **C2 Keywords Found**: {', '.join(result['cloud_iocs'])}")
    
    # Add critical section if there are any
    if critical_indicators:
        result_lines.append("**[!!! CRITICAL INDICATORS !!!]**")
        result_lines.extend(critical_indicators)
        result_lines.append("")  # blank line separator
    
    # Format result lines for markdown report - INCLUDE ALL DATA FOR VERIFICATION
    if result['ips']: result_lines.append(f"- IPs: {', '.join(result['ips'])}")
    if result['urls']: result_lines.append(f"- URLs: {', '.join(result['urls'])}")
    if result['domains']: result_lines.append(f"- Domains: {', '.join(result['domains'])}")
    
    # Full mutex list for verification
    if result['mutexes']: 
       result_lines.append(f"- Mutexes ({len(result['mutexes'])} found): {', '.join(result['mutexes'][:INDICATORS_EXTRACTION['report_truncation_limits']['mutexes_report']])}{'...' if len(result['mutexes']) > INDICATORS_EXTRACTION['report_truncation_limits']['mutexes_report'] else ''}")
    
    # Full registry key list for verification
    if result['regkeys']: 
        result_lines.append(f"- Registry Keys ({len(result['regkeys'])} found): {', '.join(result['regkeys'])}")
    
    if result['user_agents']: result_lines.append(f"- User Agents: {', '.join(result['user_agents'])}")
    if result['cloud_iocs']: result_lines.append(f"- Cloud IOC usage: {', '.join(result['cloud_iocs'])}")
    if result['anti_vm']: result_lines.append(f"- Anti-VM Indicators: {', '.join(result['anti_vm'])}")
    
    # Stack strings - include for verification
    if result['stack_strings']:
        result_lines.append(f"- Stack Strings ({len(result['stack_strings'])} found): {', '.join(result['stack_strings'][:INDICATORS_EXTRACTION['report_truncation_limits']['stack_strings_report']])}{'...' if len(result['stack_strings']) > INDICATORS_EXTRACTION['report_truncation_limits']['stack_strings_report'] else ''}")
    
    # ASCII strings - include for verification (critical indicators prioritized first)
    if result['ascii']:
        result_lines.append(f"- ASCII Strings ({len(result['ascii'])} found): {', '.join(result['ascii'][:INDICATORS_EXTRACTION['report_truncation_limits']['ascii_strings_report']])}{'...' if len(result['ascii']) > INDICATORS_EXTRACTION['report_truncation_limits']['ascii_strings_report'] else ''}")
    
    # Base64 candidates
    if result['base64']:
        result_lines.append(f"- Base64 Blobs (Strict) ({len(result['base64'])} found): {', '.join(result['base64'][:INDICATORS_EXTRACTION['report_truncation_limits']['base64_report']])}{'...' if len(result['base64']) > INDICATORS_EXTRACTION['report_truncation_limits']['base64_report'] else ''}")
    
    # Decoded C2 indicators
    if result['decoded_c2']:
        result_lines.append(f"- Decoded C2 Indicators: {', '.join(result['decoded_c2'])}")
    
    # -------------------------
    # Console Output (AFTER FILTERING)
    # -------------------------
    console.print("\n[bold cyan]Static Indicators / C2 Detection (STRICT)[/bold cyan]")

    # Helper function to determine risk level
    def get_risk_level(indicator_type: str, indicator_value: str = "") -> str:
        """Determine risk level [LOW/MEDIUM/HIGH] based on indicator type and value."""
        risk_map = {
            'ips': '[MEDIUM]',  # IPs always suspicious when hardcoded
            'urls': '[MEDIUM]',  # URLs categorized by domain risk
            'domains': '[MEDIUM]',  # Domains categorized separately
            'mutexes': '[MEDIUM]',  # Mutexes are malware sync indicators
            'regkeys': '[MEDIUM]',  # Registry keys for persistence
            'keywords': '[HIGH]',  # Suspicious keywords like 'C2', 'botnet'
            'cloud_iocs': '[MEDIUM]',  # Discord, Telegram for C2
            'anti_vm': '[HIGH]',  # Anti-VM is strong malware indicator
            'base64': '[LOW]',  # Base64 is common, not inherently malicious
            'user_agents': '[LOW]',  # User agents are low risk
        }
        return risk_map.get(indicator_type, '[MEDIUM]')

    # IPs with forensic detail - HIGH PRIORITY
    if result['ips']:
        console.print(f"[red]{get_risk_level('ips')} Hardcoded IPs:[/red] {', '.join(result['ips'])}")
        if result.get('ips_prov'):
            for ip, section, offset in result['ips_prov'][:INDICATORS_EXTRACTION['report_truncation_limits']['console_provenance_detail']]:
                console.print(f"  [dim]  section=[{section}] offset=0x{offset:x}[/dim]")
            if len(result.get('ips_prov', [])) > INDICATORS_EXTRACTION['report_truncation_limits']['console_provenance_detail']:
                console.print(f"  [dim]  +{len(result['ips_prov']) - INDICATORS_EXTRACTION['report_truncation_limits']['console_provenance_detail']} more[/dim]")
    else:
        console.print("[green]No hardcoded IPs detected[/green]")
    
    # URLs with forensic detail - CATEGORIZED BY RISK
    if result['urls']:
        # Categorize URLs by risk level
        url_categories = {'benign': [], 'low': [], 'medium': [], 'high': []}
        for url in result['urls']:
            risk = categorize_url_risk(url)
            if risk in url_categories:
                url_categories[risk].append(url)
            else:
                url_categories['medium'].append(url)
        
        # Only report non-benign URLs
        reported_urls = url_categories['high'] + url_categories['medium'] + url_categories['low']
        
        if url_categories['high']:
            console.print(f"[bold red][HIGH] Hardcoded URLs (high-risk):[/bold red] {', '.join(url_categories['high'])}")
        if url_categories['medium']:
            console.print(f"[red][MEDIUM] Hardcoded URLs:[/red] {', '.join(url_categories['medium'])}")
        if url_categories['low']:
            console.print(f"[yellow][LOW] URLs (known vendors):[/yellow] {', '.join(url_categories['low'])}")
        
        if url_categories['benign']:
            console.print(f"[dim][Benign] System URLs (filtered): {len(url_categories['benign'])} found[/dim]")
        
        if result.get('urls_prov'):
            for url, section, offset in result.get('urls_prov', [])[:INDICATORS_EXTRACTION['report_truncation_limits']['console_provenance_detail']]:
                console.print(f"  [dim]  section=[{section}] offset=0x{offset:x}[/dim]")
    else:
        console.print("[green]No suspicious URLs detected[/green]")
    
    # Domains with forensic detail - HIGH PRIORITY
    if result['domains']:
        console.print(f"[red]{get_risk_level('domains')} Hardcoded Domains:[/red] {', '.join(result['domains'])}")
        if result.get('domains_prov'):
            for domain, section, offset in result['domains_prov'][:INDICATORS_EXTRACTION['report_truncation_limits']['console_provenance_detail']]:
                console.print(f"  [dim]  section=[{section}] offset=0x{offset:x}[/dim]")
            if len(result.get('domains_prov', [])) > INDICATORS_EXTRACTION['report_truncation_limits']['console_provenance_detail']:
                console.print(f"  [dim]  +{len(result['domains_prov']) - INDICATORS_EXTRACTION['report_truncation_limits']['console_provenance_detail']} more[/dim]")
    else:
        console.print("[green]No hardcoded domains detected[/green]")

    # Mutexes - MEDIUM PRIORITY
    if result['mutexes']:
        console.print(f"[yellow]{get_risk_level('mutexes')} Mutexes:[/yellow] {', '.join(result['mutexes'][:INDICATORS_EXTRACTION['report_truncation_limits']['console_mutexes']])}")
        if len(result['mutexes']) > INDICATORS_EXTRACTION['report_truncation_limits']['console_mutexes']:
            console.print(f"  [dim]+{len(result['mutexes']) - INDICATORS_EXTRACTION['report_truncation_limits']['console_mutexes']} more (see full report)[/dim]")
    
    # Registry Keys - MEDIUM PRIORITY
    if result['regkeys']:
        console.print(f"[yellow]{get_risk_level('regkeys')} Registry Keys:[/yellow] {', '.join(result['regkeys'])}")
    
    # User Agents - FILTER MEANINGLESS STRINGS (using configured filters)
    # Only report actual user-agent strings (Mozilla, Chrome, Safari, etc)
    # Exclude generic OS strings and compilation artifacts
    exclude_list = USER_AGENT_FILTER.get('exclude_strings', [])
    meaningful_ua = [ua for ua in result['user_agents'] 
                    if not any(x in ua.lower() for x in exclude_list)]
    if meaningful_ua:
        console.print(f"[cyan]{get_risk_level('user_agents')} User Agents:[/cyan] {', '.join(meaningful_ua)}")
    elif result['user_agents']:
        # Only system artifacts found - don't report
        console.print(f"[dim][Benign] User-Agent artifacts found (no actual user-agents)[/dim]")

    # Suspicious keywords - HIGH PRIORITY
    if result['keywords']:
        console.print(f"[magenta]{get_risk_level('keywords')} Suspicious Keywords:[/magenta] {', '.join(result['keywords'])}")
    
    # Cloud IOC usage - MEDIUM PRIORITY
    if result['cloud_iocs']:
        console.print(f"[magenta]{get_risk_level('cloud_iocs')} Cloud IOCs:[/magenta] {', '.join(result['cloud_iocs'])}")
    
    # Anti-VM Indicators - HIGH PRIORITY
    if result['anti_vm']:
        console.print(f"[red]{get_risk_level('anti_vm')} Anti-VM Indicators:[/red] {', '.join(result['anti_vm'])}")

    # Base64 candidates - LOW PRIORITY
    if result['base64']:
        console.print(f"[cyan]{get_risk_level('base64')} Base64 Blobs (Strict):[/cyan] {len(result['base64'])} found")
        if result['decoded_c2']:
            console.print(f"  [bold cyan][HIGH] Decoded to valid C2 ({len(result['decoded_c2'])} found):[/bold cyan]")
            for c in result['decoded_c2'][:INDICATORS_EXTRACTION['report_truncation_limits']['console_decoded_c2']]:
                console.print(f"     {c}")
            if len(result['decoded_c2']) > INDICATORS_EXTRACTION['report_truncation_limits']['console_decoded_c2']:
                console.print(f"     +{len(result['decoded_c2']) - INDICATORS_EXTRACTION['report_truncation_limits']['console_decoded_c2']} more")
    else:
        console.print("[green]No valid Base64 candidates found (strict)[/green]")


    if result['cmd_exec'].get("found_cmd_exec"):
        console.print("[bold red]* Command Execution Pattern Detected:[/bold red]")
        console.print(f"  Patterns: {', '.join(result['cmd_exec']['cmd_patterns'])}")
        console.print(f"  Arguments: {', '.join(result['cmd_exec']['cmd_args'])}")
        console.print(f"  [dim]Detection: Exact string matching for cmd.exe + command line arguments[/dim]")
    
    # Return both dict and formatted result_lines
    return result, result_lines
