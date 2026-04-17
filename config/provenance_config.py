"""
Configuration for provenance.py (utils).
Copied from original config.py for modularization.
"""

PROVENANCE_CONFIG = {
    'source_identifiers': {
        'manifest_resource': 'PE_MANIFEST',
        'optional_header': 'PE_OPTIONAL_HEADER',
    },
    
    'resource_types': {
        'rt_manifest': 24,  # RT_MANIFEST resource type
    },
    
    'manifest_execution_levels': {
        'require_administrator': 'requireadministrator',
        'highest_available': 'highestAvailable',
        'as_invoker': 'asinvoker',
    },
    
    'pe_subsystems': {
        0: ("UNKNOWN", "Unknown subsystem"),
        1: ("NATIVE", "Native (kernel-mode) driver"),
        2: ("WINDOWS_GUI", "Windows GUI application"),
        3: ("WINDOWS_CUI", "Windows console application"),
        5: ("OS2_CUI", "OS/2 console application"),
        7: ("POSIX_CUI", "POSIX console application"),
        8: ("WINDOWS_CE_GUI", "Windows CE GUI application"),
        10: ("EFI_APPLICATION", "EFI application"),
        11: ("EFI_BOOT_SERVICE_DRIVER", "EFI boot service driver"),
        12: ("EFI_RUNTIME_DRIVER", "EFI runtime driver"),
        13: ("EFI_ROM", "EFI ROM image"),
        14: ("XBOX", "Xbox application"),
        16: ("WINDOWS_BOOT_APPLICATION", "Windows boot application"),
    }
}
