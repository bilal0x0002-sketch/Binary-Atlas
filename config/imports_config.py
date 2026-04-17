"""
Configuration for imports.py (utils).
Copied from original config.py for modularization.
"""

IMPORT_ANALYSIS_KEYWORDS = {
    'critical_apis': [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
        "CreateRemoteThread", "ZwMapViewOfSection", "NtWriteVirtualMemory"
    ],
    'suspicious_apis': [
        "WinExec", "LoadLibrary", "LoadLibraryEx", "GetProcAddress",
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "CryptCreateHash",
        "CryptGenRandom", "CryptHashData", "SetWindowsHookEx"
    ],
    'moderate_apis': [
        "WSAStartup", "send", "recv", "CreateFileA", "CreateFileW",
        "CreateProcessA", "CreateProcessW"
    ],
    'anti_debug_apis': [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
        "QueryPerformanceFrequency"
    ],
    'rat_apis': [
        "GetAsyncKeyState", "EnumWindows", "GetForegroundWindow",
        "GetWindowText", "GetWindowTextLength", "PostMessage", "SendMessage",
        "UpdateWindow", "ShellExecute", "ShellExecuteEx"
    ],
    'benign_dlls': {
        "KERNEL32.DLL", "NTDLL.DLL", "USER32.DLL", "GDI32.DLL",
        "ADVAPI32.DLL", "SHELL32.DLL", "COMCTL32.DLL", "COMDLG32.DLL",
        "SHLWAPI.DLL", "OLE32.DLL", "OLEAUT32.DLL", "WININET.DLL",
        "URLMON.DLL", "PSAPI.DLL", "IMAGEHLP.DLL", "DBGHELP.DLL",
        "WINSPOOL.DRV", "UXTHEME.DLL", "GDIPLUS.DLL", "WINMM.DLL"
    },
}
