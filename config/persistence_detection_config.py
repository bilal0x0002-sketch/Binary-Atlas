"""
Configuration for persistence_detection.py (analysis).
Copied from original config.py for modularization.
"""

PERSISTENCE_PATTERNS_CONFIG = {
    'registry_run_keys': [
        r'HKLM.*Software.*Microsoft.*Windows.*CurrentVersion.*Run',
        r'HKCU.*Software.*Microsoft.*Windows.*CurrentVersion.*Run',
        r'HKLM.*Software.*Wow6432Node.*Microsoft.*Windows.*CurrentVersion.*Run',
        r'HKCU.*Software.*Wow6432Node.*Microsoft.*Windows.*CurrentVersion.*Run',
        r'HKLM.*Software.*Microsoft.*Windows.*CurrentVersion.*RunOnce',
        r'HKCU.*Software.*Microsoft.*Windows.*CurrentVersion.*RunOnce',
    ],
    'service_apis': [
        'CreateServiceA',
        'CreateServiceW',
        'CreateServiceAsUser',
        'ChangeServiceConfig',
        'ServiceMain',
        'SetServiceStatus',
        'StartService',
    ],
    'task_scheduler_indicators': [
        'ITaskScheduler',
        'ITaskService',
        'CreateTask',
        'RegisterTask',
        'IRegisteredTask',
        'TaskScheduler',
        'TASK_',
        'at.exe',
        'schtasks',
    ],
    'startup_folder_patterns': [
        r'Startup',
        r'Start Menu',
        r'ProgramData.*Microsoft.*Windows.*Start Menu',
        r'AppData.*Roaming.*Microsoft.*Windows.*Start Menu',
        r'Shell\\Startup',
    ],
    'wmi_indicators': [
        'Win32_ProcessStartup',
        'Win32_Process',
        '__EventFilter',
        '__EventConsumer',
        'ActiveScriptEventConsumer',
        'CommandLineEventConsumer',
        'EventAggregator',
        'WbemScripting',
        "GetObject('winmgmts",
    ],
    'bho_patterns': [
        r'CLSID.*',
        r'ProgID',
        r'Browser.*Helper',
        r'IObjectWithSite',
        r'DllRegisterServer',
    ],
    'logon_script_patterns': [
        r'UserInitMprLogonScript',
        r'Logon.*Script',
        r'HKLM.*Policies.*System.*Logon',
        r'HKCU.*Policies.*System.*Logon',
        r'gptini',
        r'Machine.*Scripts.*Logon',
        r'User.*Scripts.*Logon',
    ],
}
