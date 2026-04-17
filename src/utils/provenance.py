"""
Provenance Tracking Module

Tracks where each detection comes from:
- Section + offset for binary patterns
- String location and context
- API import from specific DLL
- Mutex source
- Registry key references
"""

import hashlib
import sys
import os
import pefile
from typing import Dict, Any

# Add parent directory to path to import config
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
from config.provenance_config import PROVENANCE_CONFIG


def calculate_file_hashes(file_path: str) -> Dict[str, str]:
    """
    Calculate cryptographic hashes of the PE file.
    
    Args:
        file_path: Path to PE file
        
    Returns:
        Dict with MD5, SHA256 hashes
    """
    hashes = {}
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            
        hashes['MD5'] = hashlib.md5(content).hexdigest()
        hashes['SHA256'] = hashlib.sha256(content).hexdigest()
        hashes['SHA1'] = hashlib.sha1(content).hexdigest()
        
    except Exception as e:
        hashes['error'] = str(e)
    
    return hashes


def get_imphash(pe: pefile.PE) -> str:
    """
    Calculate import hash (ImpHash) for malware tracking.
    
    ImpHash is standard in malware detection - allows tracking samples
    with same import patterns but different compile times.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        ImpHash (MD5 of import table)
    """
    try:
        import_table = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else "UNKNOWN"
                    import_table.append(f"{dll_name}.{func_name}")
        
        import_string = ','.join(sorted(import_table))
        imphash = hashlib.md5(import_string.encode()).hexdigest()
        
        return imphash
    except Exception as e:
        return f"ERROR: {str(e)}"


def get_manifest_info(pe: pefile.PE) -> Dict[str, Any]:
    """
    Extract privilege level and UAC requirements from PE manifest.
    
    Returns info about:
    - Requested execution level (asInvoker, requireAdministrator, highestAvailable)
    - UAC virtualization
    - UIAccess
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dict with privilege and UAC information
    """
    manifest_info = {
        "has_manifest": False,
        "execution_level": "UNKNOWN",
        "uac_virtualization": "UNKNOWN",
        "ui_access": False,
        "requires_admin": False,
        "raw_manifest": None,
        "source": PROVENANCE_CONFIG['source_identifiers']['manifest_resource']
    }
    
    try:
        # Try to extract manifest from resources
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if entry.struct.Id == PROVENANCE_CONFIG['resource_types']['rt_manifest']:  # RT_MANIFEST
                    manifest_info["has_manifest"] = True
                    
                    # Look for execution level strings
                    try:
                        manifest_data = pe.get_data(
                            entry.directory.entries[0].directory.entries[0].data.struct.OffsetToData,
                            entry.directory.entries[0].directory.entries[0].data.struct.Size
                        )
                        manifest_text = manifest_data.decode('utf-8', errors='ignore')
                        manifest_info["raw_manifest"] = manifest_text
                        
                        # Parse execution level
                        require_admin_str = PROVENANCE_CONFIG['manifest_execution_levels']['require_administrator']
                        highest_avail_str = PROVENANCE_CONFIG['manifest_execution_levels']['highest_available']
                        as_invoker_str = PROVENANCE_CONFIG['manifest_execution_levels']['as_invoker']
                        
                        if require_admin_str in manifest_text.lower():
                            manifest_info["execution_level"] = "REQUIRE_ADMINISTRATOR"
                            manifest_info["requires_admin"] = True
                        elif highest_avail_str in manifest_text.lower():
                            manifest_info["execution_level"] = "HIGHEST_AVAILABLE"
                            manifest_info["requires_admin"] = True
                        elif as_invoker_str in manifest_text.lower():
                            manifest_info["execution_level"] = "AS_INVOKER"
                        
                        # Check UAC settings
                        if 'uiAccess="true"' in manifest_text.lower():
                            manifest_info["ui_access"] = True
                            
                    except Exception:
                        pass
    
    except Exception as e:
        manifest_info["error"] = str(e)
    
    return manifest_info


def check_subsystem_privileges(pe: pefile.PE) -> Dict[str, str]:
    """
    Check PE subsystem to determine privilege context.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dict with subsystem and privilege info
    """
    subsystem = pe.OPTIONAL_HEADER.Subsystem
    subsystem_name, subsystem_desc = PROVENANCE_CONFIG['pe_subsystems'].get(subsystem, ("UNKNOWN", "Unknown"))
    
    # Determine privilege requirement
    if subsystem == 1:  # NATIVE
        privilege_context = "KERNEL/SYSTEM"
    elif subsystem in [2, 3]:  # WINDOWS_GUI or WINDOWS_CUI
        privilege_context = "USER"
    else:
        privilege_context = "SPECIAL"
    
    return {
        "subsystem_id": subsystem,
        "subsystem_name": subsystem_name,
        "subsystem_description": subsystem_desc,
        "privilege_context": privilege_context,
        "source": PROVENANCE_CONFIG['source_identifiers']['optional_header']
    }
