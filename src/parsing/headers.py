# headers.py
"""
PE Headers Analysis Module

Analyzes PE (Portable Executable) file headers:
- DOS Header: Legacy MS-DOS compatibility header
- File Header: Machine type, section count, characteristics
- Optional Header: Entry point, image base, subsystem type

This helps identify:
- Target architecture (x86, x64, ARM)
- File characteristics (executable, DLL, system driver)
- Memory layout and subsystem requirements
"""

import pefile
from typing import Any, List

def analyze_headers(pe: pefile.PE, console: Any) -> List[str]:
    """
    Analyze DOS, File, and Optional headers of PE executable.
    
    Args:
        pe: pefile.PE object representing the PE file
        console: Rich Console for output (prints table format)
    
    Returns:
        List[str]: Analysis output lines (currently empty, output goes to console)
    
    Analysis includes:
        - DOS Header: Magic, file offset to PE header
        - File Header: Machine type, number of sections, characteristics flags
        - Optional Header: Magic, entry point, image base, subsystem, DLL characteristics
    
    Example:
        >>> analyze_headers(pe, console)
        # Outputs formatted tables to console showing PE header fields
    """
    
    output_lines = []

    # Parent section: PE Headers
    output_lines.append("\nPE Headers")
    output_lines.append("=" * 40)
    
    # Print parent to console
    console.print("\n[bold]PE Headers[/bold]")

    # DOS Header (as subsection)
    output_lines.append("\n[!] DOS Header")
    output_lines.append(f"  e_magic:  {hex(pe.DOS_HEADER.e_magic)}")
    output_lines.append(f"  e_lfanew: {hex(pe.DOS_HEADER.e_lfanew)}")
    
    # Print to console
    console.print("\n[bold cyan][!] DOS Header[/bold cyan]")
    console.print(f"  e_magic:  {hex(pe.DOS_HEADER.e_magic)}")
    console.print(f"  e_lfanew: {hex(pe.DOS_HEADER.e_lfanew)}")

    # File Header (as subsection)
    fh = pe.FILE_HEADER
    output_lines.append("\n[!] File Header")
    output_lines.append(f"  Machine:         {hex(fh.Machine)}")
    output_lines.append(f"  Sections:        {fh.NumberOfSections}")
    output_lines.append(f"  Characteristics: {hex(fh.Characteristics)}")
    
    # Print to console
    console.print("\n[bold cyan][!] File Header[/bold cyan]")
    console.print(f"  Machine:         {hex(fh.Machine)}")
    console.print(f"  Sections:        {fh.NumberOfSections}")
    console.print(f"  Characteristics: {hex(fh.Characteristics)}")

    # Optional Header (as subsection)
    opt = pe.OPTIONAL_HEADER
    output_lines.append("\n[!] Optional Header")
    output_lines.append(f"  Magic:       {hex(opt.Magic)}")
    output_lines.append(f"  EntryPoint:  {hex(opt.AddressOfEntryPoint)}")
    output_lines.append(f"  ImageBase:   {hex(opt.ImageBase)}")
    output_lines.append(f"  SizeOfImage: {hex(opt.SizeOfImage)}")
    output_lines.append(f"  Subsystem:   {opt.Subsystem}")
    
    # Print to console
    console.print("\n[bold cyan][!] Optional Header[/bold cyan]")
    console.print(f"  Magic:       {hex(opt.Magic)}")
    console.print(f"  EntryPoint:  {hex(opt.AddressOfEntryPoint)}")
    console.print(f"  ImageBase:   {hex(opt.ImageBase)}")
    console.print(f"  SizeOfImage: {hex(opt.SizeOfImage)}")
    console.print(f"  Subsystem:   {opt.Subsystem}")

    return output_lines
