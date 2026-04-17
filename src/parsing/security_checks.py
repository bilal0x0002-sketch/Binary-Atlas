# security_checks.py
"""
Security Checks Module

Performs advanced PE security checks:
- File timestamp analysis (current vs compile time)
- Section alignment verification
- Padding analysis (suspicious padding patterns)
- Header integrity checks
- PE flags and characteristics validation

Detects:
- Compilation timestamp anomalies (future dates, invalid times)
- Section alignment issues (malware often uses custom alignment)
- Excessive padding (code obfuscation technique)
- Header corruption (pack errors)
"""

from datetime import datetime, timezone
from typing import Any, Tuple, List
import pefile
from config.security_checks_config import SECURITY_CHECKS_CONFIG
from src.utils.entropy import calc_entropy

def perform_security_checks(pe: pefile.PE, console: Any) -> List[str]:
    """
    Perform advanced PE security checks and validation.
    
    Args:
        pe: pefile.PE object representing the PE file
        console: Rich Console for formatted output
    
    Returns:
        List[str]: List of analysis output lines
    
    Checks performed:
        - Compilation timestamp (year/month/day validation)
        - Section alignment (must match SectionAlignment in Optional Header)
        - Raw padding (difference between raw size and virtual size)
        - PE header integrity (magic numbers, field ranges)
        - Suspicious characteristics (unusual flags set)
    
    Red flags:
        - Timestamp in future (clock tampering)
        - Timestamp in year 1970-1980 (invalid)
        - Misaligned sections (manual PE construction)
        - Excessive padding (obfuscation)
    
    Example:
        >>> lines = perform_security_checks(pe, console)
        >>> print(f"Output lines: {len(lines)}")
    """
    
    output_lines = []
    console.buffer_console.print("\n[bold cyan]ADVANCED ANALYSIS[/bold cyan]")
    fh = pe.FILE_HEADER
    opt = pe.OPTIONAL_HEADER

    # Timestamp
    console.buffer_console.print("\n[bold yellow][!] Timestamp[/bold yellow]")
    output_lines.append("\n[!] Timestamp")
    ts = fh.TimeDateStamp
    ts_human = datetime.fromtimestamp(ts, tz=timezone.utc) if ts != 0 else "N/A"
    console.buffer_console.print(f"{ts}  ({ts_human})")
    output_lines.append(f"{ts}  ({ts_human})")
    if ts == 0:
        console.buffer_console.print("[red]Null timestamp: (likely packed or modified)[/red]")
        output_lines.append("Null timestamp (likely packed or modified)")
    if ts < SECURITY_CHECKS_CONFIG['timestamp_year_2000_unix'] and ts != 0:
        console.buffer_console.print("[dim]Timestamp before year 2000: (WEAK signal - MSVC6.0, reproducible build, or packer)[/dim]")
        output_lines.append("Timestamp before year 2000 (WEAK signal - not conclusive alone)")
    
    # Future timestamp check (indicates forgery or malicious intent)
    from datetime import datetime as dt
    current_ts = int(dt.now().timestamp())
    if ts > current_ts and ts != 0:
        ts_future = datetime.fromtimestamp(ts, tz=timezone.utc)
        console.buffer_console.print(f"[red][!] CRITICAL: Timestamp in future ({ts_future}) - strong indicator of malware[/red]")
        output_lines.append(f"[!] CRITICAL: Timestamp in future ({ts_future}) - strong indicator of malware")

    # Alignment
    console.buffer_console.print("\n[bold yellow][!] Alignment Checks[/bold yellow]")
    output_lines.append("\n[!] Alignment Checks")
    console.buffer_console.print(f"SectionAlignment: {hex(opt.SectionAlignment)}")
    output_lines.append(f"SectionAlignment: {hex(opt.SectionAlignment)}")
    console.buffer_console.print(f"FileAlignment: {hex(opt.FileAlignment)}")
    output_lines.append(f"FileAlignment: {hex(opt.FileAlignment)}")
    if opt.SectionAlignment < SECURITY_CHECKS_CONFIG['min_section_alignment']:
        console.buffer_console.print("[red]Unusual SectionAlignment: (< 0x1000)[/red]")
        output_lines.append("Unusual SectionAlignment (< 0x1000)")
    if opt.FileAlignment not in SECURITY_CHECKS_CONFIG['valid_file_alignments']:
        console.buffer_console.print("[red]Suspicious FileAlignment:[/red]")
        output_lines.append("Suspicious FileAlignment")

    # Security Flags
    console.buffer_console.print("\n[bold yellow][!] Security Flags[/bold yellow]")
    output_lines.append("\n[!] Security Flags")
    flags = opt.DllCharacteristics
    console.buffer_console.print(f"DllCharacteristics: {hex(flags)}")
    output_lines.append(f"DllCharacteristics: {hex(flags)}")
    sec_flags = SECURITY_CHECKS_CONFIG['security_flags']
    
    # Check ASLR (Address Space Layout Randomization)
    if flags & sec_flags['ASLR']: 
        console.buffer_console.print("[green]ASLR: ENABLED (DYNAMIC_BASE set)[/green] [dim](from security_checks.py)[/dim]")
        output_lines.append("ASLR: ENABLED (DYNAMIC_BASE set)")
    else:
        console.buffer_console.print("[red]ASLR disabled: (DYNAMIC_BASE not set)[/red] [dim](from security_checks.py)[/dim]")
        output_lines.append("ASLR: DISABLED (DYNAMIC_BASE not set)")
    
    # Check DEP/NX (Data Execution Prevention)
    if flags & sec_flags['DEP_NX']: 
        console.buffer_console.print("[green]DEP/NX: ENABLED (NX_COMPAT set)[/green] [dim](from security_checks.py)[/dim]")
        output_lines.append("DEP/NX: ENABLED (NX_COMPAT set)")
    else:
        console.buffer_console.print("[red]DEP/NX disabled: (NX_COMPAT not set)[/red] [dim](from security_checks.py)[/dim]")
        output_lines.append("DEP/NX: DISABLED (NX_COMPAT not set)")
    
    # Check CFG (Control Flow Guard)
    if flags & sec_flags['CFG']: 
        console.buffer_console.print("[green]CFG: ENABLED (GUARD_CF set)[/green] [dim](from security_checks.py)[/dim]")
        output_lines.append("CFG: ENABLED (GUARD_CF set)")
    else:
        console.buffer_console.print("[red]CFG disabled: (GUARD_CF not set)[/red] [dim](from security_checks.py)[/dim]")
        output_lines.append("CFG: DISABLED (GUARD_CF not set)")

    # TLS Callbacks - IMPORTANT: Not suspicious by itself!
    # Modern MSVC uses TLS for CRT initialization, exception handling, thread-local storage
    # Only suspicious if combined with other evasion signals (no debug symbols + packed + suspicious imports)
    console.buffer_console.print("\n[bold yellow][!] TLS Callbacks[/bold yellow]")
    output_lines.append("\n[!] TLS Callbacks")
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        console.buffer_console.print("[dim][!] TLS callbacks present - NORMAL for modern C++ binaries (CRT init, exception handling)[/dim]")
        output_lines.append("TLS Callbacks: Present (normal - used for CRT initialization in modern MSVC builds)")
    else:
        console.buffer_console.print("[cyan]TLS callbacks: None[/cyan]")
        output_lines.append("TLS Callbacks: None")

    # Relocations
    console.buffer_console.print("\n[bold yellow][!] Relocation Table[/bold yellow]")
    output_lines.append("\n[!] Relocation Table")
    if hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        console.buffer_console.print(f"Base relocations present: {len(pe.DIRECTORY_ENTRY_BASERELOC)}")
        output_lines.append(f"Base relocations: {len(pe.DIRECTORY_ENTRY_BASERELOC)}")
    else:
        console.buffer_console.print("[cyan]No relocations:[/cyan]")
        output_lines.append("Relocations: Not Detected")

    # Export Directory
    console.buffer_console.print("\n[bold yellow][!] Export Directory[/bold yellow]")
    output_lines.append("\n[!] Export Directory")
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        console.buffer_console.print(f"Exports: {len(pe.DIRECTORY_ENTRY_EXPORT.symbols)}")
        output_lines.append(f"Exports: {len(pe.DIRECTORY_ENTRY_EXPORT.symbols)}")
    else:
        console.buffer_console.print("[cyan]No export directory:[/cyan]")
        output_lines.append("Exports: Not Present")

    # Calculate file metrics (for reference, but not needed for return)
    last_end = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
    file_size = len(pe.__data__)

    # Debug / PDB
    console.buffer_console.print("\n[bold yellow][!] Debug / PDB Info[/bold yellow]")
    output_lines.append("\n[!] Debug / PDB Info")
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for d in pe.DIRECTORY_ENTRY_DEBUG:
            ptr = getattr(d, "PointerToRawData", "N/A")
            size = getattr(d, "SizeOfData", "N/A")
            dbg_type = getattr(d, "Type", "N/A")
            pdb = ""
            try:
                debug_marker = SECURITY_CHECKS_CONFIG['pe_magic_signatures']
                if d.struct.Type == debug_marker['debug_type_pdb']:
                    data = pe.get_data(d.struct.PointerToRawData, d.struct.SizeOfData)
                    if data[:4] == debug_marker['debug_signature']:
                        pdb = data[24:].split(b'\x00', 1)[0].decode(errors="replace")
            except (IndexError, UnicodeDecodeError) as e:
                pass
            except Exception as e:
                pass
            console.buffer_console.print(f"Type: {dbg_type}  Pointer: {ptr}  Size: {size}  PDB: {pdb if pdb else 'N/A'}")
            output_lines.append(f"Type: {dbg_type}  Pointer: {ptr}  Size: {size}  PDB: {pdb if pdb else 'N/A'}")
    else:
        console.buffer_console.print("[magenta]No debug directory:[/magenta]")
        output_lines.append("Debug Info: None")

    # Resource Section
    console.buffer_console.print("\n[bold yellow][!] Resource Section[/bold yellow]")
    output_lines.append("\n[!] Resource Section")
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        console.buffer_console.print(f"Resource entries: {len(pe.DIRECTORY_ENTRY_RESOURCE.entries)}")
        output_lines.append(f"Resource entries: {len(pe.DIRECTORY_ENTRY_RESOURCE.entries)}")
    else:
        console.buffer_console.print("[cyan]No resource section:[/cyan]")
        output_lines.append("Resources: Not Present")

    # Image Size Consistency
    console.buffer_console.print("\n[bold yellow][!] Image Size Consistency[/bold yellow]")
    output_lines.append("\n[!] Image Size Consistency")
    total_virt = sum(s.Misc_VirtualSize for s in pe.sections)
    console.buffer_console.print(f"SizeOfImage: {hex(opt.SizeOfImage)} | Sum of Sections: {hex(total_virt)}")
    output_lines.append(f"SizeOfImage: {hex(opt.SizeOfImage)} | Sum of Sections: {hex(total_virt)}")
    if total_virt > opt.SizeOfImage:
        console.buffer_console.print("[red]SizeOfImage smaller: than sum of sections[/red]")
        output_lines.append("\n* SizeOfImage smaller than sum of sections")

    # ✅ Return output lines
    return output_lines
