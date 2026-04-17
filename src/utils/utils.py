# utils.py
import pefile
from rich.console import Console
import os
import sys
import subprocess
import hashlib
from subprocess import DEVNULL

# Add parent directory to path to import config
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
from config.utils_config import PE_VALIDATION_CONFIG

console = Console()

def load_pe_file(path):
    """
    Load and validate PE file with comprehensive error handling.
    
    Args:
        path: Path to PE file
        
    Returns:
        pefile.PE object if valid, None if invalid
    """
    try:
        # Pre-validation checks
        if not os.path.exists(path):
            console.print(f"[red]✗ File not found: {path}[/red]")
            return None
        
        file_size = os.path.getsize(path)
        if file_size < PE_VALIDATION_CONFIG['min_file_size']:
            console.print(f"[red]✗ File too small to be valid PE ({file_size} bytes)[/red]")
            return None
        
        # Check file signature
        with open(path, "rb") as f:
            magic = f.read(2)
            if magic != PE_VALIDATION_CONFIG['pe_magic_signature']:
                console.print(f"[red]✗ Invalid PE signature (expected MZ, got {magic!r})[/red]")
                return None
        
        # Parse PE
        pe = pefile.PE(path, fast_load=False)
        
        # Validate PE structure
        if not hasattr(pe, "DOS_HEADER") or not hasattr(pe, "FILE_HEADER"):
            console.print("[red]✗ Invalid PE structure: missing required headers[/red]")
            return None
        
        # Validate machine type
        valid_machines = PE_VALIDATION_CONFIG['valid_machine_types']
        if pe.FILE_HEADER.Machine not in valid_machines:
            console.print(f"[yellow]⚠ Unusual machine type: 0x{pe.FILE_HEADER.Machine:04x}[/yellow]")
        
        return pe
        
    except pefile.PEFormatError as e:
        console.print(f"[red]✗ PE parsing error: {e}[/red]")
        return None
    except PermissionError:
        console.print(f"[red]✗ Permission denied: cannot read {path}[/red]")
        return None
    except OSError as e:
        console.print(f"[red]✗ OS error reading file: {e}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]✗ Unexpected error loading PE: {e}[/red]")
        return None


def is_known_good_hash(file_path: str) -> bool:
    """
    Verify file hash against known legitimate Windows binaries.
    
    Currently disabled - hash database would be too large to maintain.
    Use filename + location verification instead.
    
    Args:
        file_path: Path to PE file
        
    Returns:
        False (disabled - use filename check instead)
    """
    return False


def is_windows_trusted_signature(file_path: str) -> bool:
    """
    Check if binary has a VALID signature that Windows trusts.
    
    This leverages Windows' own signature verification - if Windows trusts it,
    we trust it. No hardcoded whitelists.
    
    Args:
        file_path: Path to PE file
        
    Returns:
        True if Windows verifies the signature as valid, False if unsigned/invalid
    """
    try:
        # Use WinVerifyTrust API through PowerShell to check signature
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             f'try {{ '
             f'$cert = (Get-AuthenticodeSignature -FilePath "{file_path}").Status; '
             f'if ($cert -eq "Valid") {{ exit 0 }} '
             f'else {{ exit 1 }} '
             f'}} catch {{ exit 1 }}'],
            stdout=subprocess.PIPE,
            stderr=DEVNULL,
            timeout=5
        )
        return result.returncode == 0
    except:
        # If we can't check, assume unsigned (fail-safe)
        return False


def is_microsoft_signed_system_binary(file_path: str) -> bool:
    """
    Check if binary is BOTH:
    1. Located in protected Windows system directory (System32/SysWOW64)
    2. Has valid Authenticode signature (Windows verified)
    
    This leverages Windows' trust model - if Windows signed it and it's
    in System32, it's safe from malware analysis perspective.
    
    Args:
        file_path: Path to PE file
        
    Returns:
        True only if binary is in System32/SysWOW64 AND has valid signature
    """
    try:
        # First check location - must be in system directory
        abs_path = os.path.abspath(file_path).lower()
        system_dirs = [
            os.path.expandvars(r'%WINDIR%\System32').lower(),
            os.path.expandvars(r'%WINDIR%\SysWOW64').lower(),
            os.path.expandvars(r'%WINDIR%\sysnative').lower(),
        ]
        
        in_system_dir = any(abs_path.startswith(d) for d in system_dirs)
        if not in_system_dir:
            return False
        
        # Then check it has valid signature (Windows-verified)
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             f'$sig = Get-AuthenticodeSignature -FilePath "{file_path}"; '
             'if ($sig.Status -eq "Valid") {{ Write-Host "VALID"; exit 0 }} else {{ exit 1 }}'],
            stdout=subprocess.PIPE,
            stderr=DEVNULL,
            timeout=5
        )
        
        return result.returncode == 0
    except:
        return False


def is_system_binary(file_path: str) -> bool:
    """
    Check if binary is located in protected Windows system directories.
    
    Context awareness: System binaries in System32/SysWOW64 are trustworthy
    and should not be flagged as malware.
    
    Args:
        file_path: Path to PE file
        
    Returns:
        True if binary is in System32 or SysWOW64 directory, False otherwise
    """
    try:
        abs_path = os.path.abspath(file_path).lower()
        
        # Get Windows system directories
        system_dirs = [
            os.path.expandvars(r'%WINDIR%\System32').lower(),
            os.path.expandvars(r'%WINDIR%\SysWOW64').lower(),
            os.path.expandvars(r'%WINDIR%\sysnative').lower(),
        ]
        
        # Check if file is in any system directory
        for sys_dir in system_dirs:
            if abs_path.startswith(sys_dir):
                return True
        
        return False
    except:
        # If we can't determine, assume it's not a system binary
        return False

