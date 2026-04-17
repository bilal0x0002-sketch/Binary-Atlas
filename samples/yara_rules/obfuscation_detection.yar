/*
Obfuscation and Anti-Analysis Detection Rules
Detects techniques used to evade analysis and hide malware behavior
*/

rule Anti_Debugging
{
    meta:
        author = "Malware Analysis"
        description = "Detects anti-debugging API calls combined with evasion logic"
        severity = "high"
        category = "anti-analysis"

    strings:
        // Core anti-debug APIs (these are the real indicators)
        $debug1 = "IsDebuggerPresent" ascii
        $debug2 = "CheckRemoteDebuggerPresent" ascii
        $debug3 = "NtQueryInformationProcess" ascii
        
        // Timing checks (only suspicious if COMBINED with debugger checks - not alone!)
        $timing1 = "GetTickCount" ascii
        $timing2 = "QueryPerformanceCounter" ascii
        
        // Evasion patterns (bytecode for rdtsc, cpuid, etc.)
        $rdtsc = { 0F 31 }  // rdtsc instruction
        $cpuid = { 0F A2 }  // cpuid instruction

    condition:
        // Strong signal: Multiple debugger detection APIs
        (2 of ($debug1, $debug2, $debug3)) 
        // OR: Debugger check + timing check together (pattern of anti-debug evasion)
        or (($debug1 or $debug2 or $debug3) and ($timing1 or $timing2))
        // OR: Hardware-level anti-debug (rdtsc, cpuid bytecode)
        or ($rdtsc or $cpuid)
}

rule Anti_VM_Detection
{
    meta:
        author = "Malware Analysis"
        description = "Detects virtual machine/sandbox evasion techniques"
        severity = "high"
        category = "anti-analysis"

    strings:
        $s1 = "VMXh" ascii
        $s2 = "Hyper-V" ascii wide
        $s3 = "VirtualBox" ascii wide
        $s4 = "QEMU" ascii
        $s5 = "parallels" nocase ascii wide
        $s6 = "xen" nocase ascii
        $s7 = /WMware|VirtualPC|Bochs/ nocase ascii wide
        $registry = "HKEY_LOCAL_MACHINE" ascii wide
        $dll = "vboxmouse.dll" nocase ascii

    condition:
        2 of ($s*) or ($registry and $dll)
}

rule Process_Injection
{
    meta:
        author = "Malware Analysis"
        description = "Detects code injection techniques"
        severity = "high"
        category = "anti-analysis"

    strings:
        $s1 = "CreateRemoteThread" ascii
        $s2 = "WriteProcessMemory" ascii
        $s3 = "VirtualAlloc" ascii
        $s4 = "SetThreadContext" ascii
        $s5 = "ResumeThread" ascii
        $s6 = "NtCreateThreadEx" ascii
        $s7 = "RtlCreateUserThread" ascii

    condition:
        3 of them
}

rule DLL_Injection
{
    meta:
        author = "Malware Analysis"
        description = "Detects DLL injection patterns"
        severity = "high"
        category = "anti-analysis"

    strings:
        $s1 = "LoadLibrary" ascii wide
        $s2 = "GetProcAddress" ascii
        $s3 = "CreateRemoteThread" ascii
        $s4 = "VirtualAllocEx" ascii
        $s5 = "WriteProcessMemory" ascii
        $dll = /\.dll/ nocase ascii

    condition:
        4 of ($s*) and $dll
}

rule Hooks_and_Detours
{
    meta:
        author = "Malware Analysis"
        description = "Detects API hooking and function detouring"
        severity = "high"
        category = "anti-analysis"

    strings:
        $s1 = "SetWindowsHookEx" ascii
        $s2 = "UnhookWindowsHookEx" ascii
        $s3 = "IAT" ascii
        $s4 = "hook" nocase ascii
        $s5 = "detour" nocase ascii
        $pattern = /mov.*jmp|push.*ret/ ascii

    condition:
        2 of ($s*) or $pattern
}

rule Code_Obfuscation
{
    meta:
        author = "Malware Analysis"
        description = "Detects code obfuscation patterns"
        severity = "medium"
        category = "obfuscation"

    strings:
        $s1 = "obfuscat" nocase ascii
        $s2 = "polymorphic" nocase ascii
        $s3 = "metamorphic" nocase ascii
        $s4 = "shellcode" nocase ascii
        $enc1 = "CryptEncrypt" ascii
        $enc2 = "XOR" ascii
        $enc3 = "ROT13" ascii nocase

    condition:
        2 of ($s*) or (2 of ($enc*))
}

rule String_Encryption
{
    meta:
        author = "Malware Analysis"
        description = "Detects encrypted/obfuscated strings"
        severity = "medium"
        category = "obfuscation"

    strings:
        $enc1 = "CryptDecrypt" ascii
        $enc2 = "crypto" nocase ascii
        $enc3 = "decrypt" nocase ascii
        $enc4 = "decipher" nocase ascii
        $enc5 = "base64" nocase ascii
        $entropy = /[A-Za-z0-9+\/=]{50,}/ ascii

    condition:
        2 of ($enc*) or $entropy
}

rule Packer_Generic
{
    meta:
        author = "Malware Analysis"
        description = "Generic packer detection patterns"
        severity = "high"
        category = "packer"

    strings:
        $s1 = "packer" nocase ascii
        $s2 = "compressed" nocase ascii
        $s3 = "packed" nocase ascii
        $s4 = "UPX" ascii
        $s5 = "ASPack" ascii
        $s6 = "PECompact" ascii
        $s7 = "nPack" ascii
        $exe = ".exe" ascii

    condition:
        2 of ($s*) and $exe
}

rule UPX_Packed
{
    meta:
        author = "Malware Analysis"
        description = "Detects UPX packed executables"
        severity = "medium"
        category = "packer"
        family = "UPX"

    strings:
        $s1 = "UPX" ascii
        $s2 = "upx!" ascii
        $magic = { 55 50 58 21 } // UPX!

    condition:
        $magic or 2 of ($s*)
}

rule PECompact_Packed
{
    meta:
        author = "Malware Analysis"
        description = "Detects PECompact packed executables"
        severity = "medium"
        category = "packer"
        family = "PECompact"

    strings:
        $s1 = "PECompact" ascii
        $s2 = "pecompact" nocase ascii
        $c1 = "compact" nocase ascii

    condition:
        2 of them
}

rule Polymorphic_Signature
{
    meta:
        author = "Malware Analysis"
        description = "Detects polymorphic engine signatures"
        severity = "high"
        category = "obfuscation"

    strings:
        $s1 = "polymorphic" nocase ascii
        $s2 = "mutation" nocase ascii wide
        $s3 = "variant" nocase ascii wide
        $s4 = "generation" nocase ascii
        $s5 = "generate" nocase ascii

    condition:
        2 of them
}

rule Metamorphic_Signature
{
    meta:
        author = "Malware Analysis"
        description = "Detects metamorphic malware engines"
        severity = "critical"
        category = "obfuscation"

    strings:
        $s1 = "metamorphic" nocase ascii
        $s2 = "self-modifying" nocase ascii wide
        $s3 = "rewrite" nocase ascii
        $s4 = "regenerate" nocase ascii
        $code = /WriteProcessMemory.*VirtualAlloc/ ascii

    condition:
        2 of ($s*) or $code
}

rule Anti_Sandbox
{
    meta:
        author = "Malware Analysis"
        description = "Detects sandbox evasion techniques"
        severity = "high"
        category = "anti-analysis"

    strings:
        $s1 = "sandbox" nocase ascii
        $s2 = "cuckoo" nocase ascii
        $s3 = "analyze" nocase ascii
        $s4 = "sleep" ascii wide
        $s5 = /GetTickCount|Sleep/ ascii

    condition:
        2 of them
}
