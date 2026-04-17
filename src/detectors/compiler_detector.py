"""
Compiler and language runtime detection from PE metadata and imports.

Identifies the compiler/toolchain used to build the binary (MSVC, GCC, Rust, Go, Clang, etc)
based on imports, sections, strings, and debug information.
"""

from typing import Dict, Any, List


def detect_compiler(pe: Any, all_imports: List[str], debug_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect compiler/language runtime from PE metadata.
    
    Args:
        pe: pefile.PE object
        all_imports: List of all imported DLLs
        debug_info: Debug directory information
    
    Returns:
        Dict with detected compilers and confidence levels
    """
    result = {
        "detected_compilers": [],
        "language_runtimes": [],
        "compiler_version": None,
        "build_info": []
    }
    
    if not pe or not all_imports:
        return result
    
    # ==================== MSVC DETECTION ====================
    if any(dll in all_imports for dll in ["msvcrt.dll", "msvcp120.dll", "msvcp140.dll", "msvcp120d.dll"]):
        result["detected_compilers"].append("Microsoft Visual C++")
        
        # Detect MSVC version from CRT DLL
        if "msvcp140.dll" in all_imports:
            result["compiler_version"] = "MSVC 2015+ (VC14)"
        elif "msvcp120.dll" in all_imports:
            result["compiler_version"] = "MSVC 2013 (VC12)"
        elif "msvcrt.dll" in all_imports:
            result["compiler_version"] = "MSVC 6.0 - 2012"
    
    # ==================== GCC/MinGW DETECTION ====================
    if any(dll in all_imports for dll in ["libgcc_s.dll", "libstdc++.dll", "libwinpthread.dll"]):
        result["detected_compilers"].append("GCC / MinGW")
        result["language_runtimes"].append("GNU C/C++ Runtime")
    
    # ==================== RUST DETECTION ====================
    # Rust binaries usually statically link stdlib but have distinctive patterns
    # Check for Rust panic hooks and std library symbols
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        try:
            exports = [exp.name.decode('utf-8', errors='ignore') for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols]
            if any('rust' in exp.lower() or 'panic' in exp.lower() for exp in exports):
                result["detected_compilers"].append("Rust")
        except:
            pass
    
    # ==================== GO DETECTION ====================
    # Go binaries have distinctive section names and runtime
    section_names = []
    if hasattr(pe, 'sections'):
        try:
            section_names = [section.Name.decode('utf-8', errors='ignore').strip('\x00') for section in pe.sections]
        except:
            pass
    
    if any(name.startswith('.go') for name in section_names):
        result["detected_compilers"].append("Go")
    
    # Go runtime strings typically appear
    if any('golang' in section for section in section_names):
        result["detected_compilers"].append("Go")
    
    # ==================== DEBUG INFO DETECTION ====================
    # PDB path reveals compiler info
    if debug_info.get("pdb_path"):
        pdb_path = debug_info["pdb_path"].lower()
        
        if "msvc" in pdb_path or "vc" in pdb_path:
            if "MSVC" not in result["detected_compilers"]:
                result["detected_compilers"].append("Microsoft Visual C++ (from PDB)")
        
        if "clang" in pdb_path:
            result["detected_compilers"].append("Clang")
        
        if "gcc" in pdb_path or "mingw" in pdb_path:
            if "GCC" not in result["detected_compilers"]:
                result["detected_compilers"].append("GCC (from PDB)")
    
    # ==================== CLANG DETECTION ====================
    # Clang may use similar CRT but has different section layout
    # Check for Clang-specific sections or symbols
    if any(section.startswith('.text') for section in section_names):
        # This is common but Clang tends to have specific alignment patterns
        pass
    
    # ==================== .NET DETECTION ====================
    if any(dll in all_imports for dll in ["mscoree.dll"]):
        result["language_runtimes"].append(".NET Framework")
        if "msvcrt.dll" in all_imports:
            result["build_info"].append("Native wrapper with .NET integration (C++/CLI)")
    
    # ==================== TIMESTAMP-BASED COMPILER HINTS ====================
    if hasattr(pe, 'FILE_HEADER'):
        try:
            timestamp = pe.FILE_HEADER.TimeDateStamp
            
            # Null timestamp often indicates Rust or recent Go builds
            if timestamp == 0:
                if "Rust" not in result["detected_compilers"]:
                    result["build_info"].append("Reproducible build (no timestamp) - common in Rust/Go")
            
            # Pre-2000 timestamps can indicate old MSVC6 or reproducible builds
            # This is a WEAK signal - only combine with packing/missing imports for detection
            if timestamp < 946684800:  # Jan 1, 2000
                result["build_info"].append("Pre-2000 timestamp (WEAK signal - could be MSVC 6.0, reproducible build, or packer)")
        except:
            pass
    
    # ==================== SECTION ENTROPY HINTS ====================
    # Rust binaries often have higher entropy sections due to monomorphization
    high_entropy_sections = debug_info.get("high_entropy_sections", [])
    if len(high_entropy_sections) > 2:
        result["build_info"].append("Multiple high-entropy sections - possible Rust or Go")
    
    # Remove duplicates while preserving order
    result["detected_compilers"] = list(dict.fromkeys(result["detected_compilers"]))
    result["language_runtimes"] = list(dict.fromkeys(result["language_runtimes"]))
    result["build_info"] = list(dict.fromkeys(result["build_info"]))
    
    return result
