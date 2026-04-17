/*
Behavioral Detection Rules
Detects malicious behavior patterns and C2 communication
*/

rule Command_Execution
{
    meta:
        author = "Malware Analysis"
        description = "Detects command execution capabilities with obfuscation/hiding"
        severity = "high"
        category = "behavior"

    strings:
        $s1 = "cmd.exe" ascii wide
        $s2 = "cmd /c" ascii
        $s3 = "ShellExecute" ascii
        $s4 = "WinExec" ascii
        $s5 = "system(" nocase ascii
        $hide1 = "cmd" nocase

    condition:
        ($s1 and ($s3 or $s4)) or (all of ($s*) and #hide1 > 5) or (4 of ($s*))
}

rule File_Operations
{
    meta:
        author = "Malware Analysis"
        description = "Detects suspicious file operations patterns"
        severity = "medium"
        category = "behavior"

    strings:
        $write1 = "CreateFile" ascii
        $write2 = "WriteFile" ascii
        $write3 = "DeleteFile" ascii
        $read1 = "ReadFile" ascii
        $read2 = "FindFirstFile" ascii
        $suspect1 = "tmp" nocase ascii
        $suspect2 = "temp" nocase ascii
        $suspect3 = "\\temp" ascii

    condition:
        ($write1 and $write2 and $write3) or (($write1 or $write2) and ($read1 or $read2) and 3 of ($suspect*))
}

rule Registry_Operations
{
    meta:
        author = "Malware Analysis"
        description = "Detects suspicious registry operations (persistence)"
        severity = "high"
        category = "behavior"

    strings:
        $s1 = "RegOpenKeyEx" ascii
        $s2 = "RegSetValueEx" ascii
        $s3 = "RegCreateKeyEx" ascii
        $s4 = "RegDeleteKey" ascii
        $s5 = "HKEY_LOCAL_MACHINE" ascii wide
        $s6 = "Run" ascii wide
        $s7 = "Startup" ascii wide

    condition:
        3 of ($s1,$s2,$s3,$s4) and 2 of ($s5,$s6,$s7)
}

rule Network_Communication
{
    meta:
        author = "Malware Analysis"
        description = "Detects network communication APIs"
        severity = "high"
        category = "behavior"

    strings:
        $s1 = "socket" ascii wide
        $s2 = "connect" ascii
        $s3 = "InternetOpen" ascii
        $s4 = "HttpOpenRequest" ascii
        $s5 = "URLDownloadToFile" ascii
        $s6 = "WinInet" ascii
        $s7 = "WinHTTP" ascii

    condition:
        3 of them
}

rule Process_Creation
{
    meta:
        author = "Malware Analysis"
        description = "Detects process creation/manipulation"
        severity = "medium"
        category = "behavior"

    strings:
        $s1 = "CreateProcess" ascii
        $s2 = "CreateProcessEx" ascii
        $s3 = "spawn" nocase ascii
        $s4 = "fork" nocase ascii
        $s5 = "exec" nocase ascii

    condition:
        2 of them
}

rule Memory_Manipulation
{
    meta:
        author = "Malware Analysis"
        description = "Detects suspicious memory operations (requires API combination)"
        severity = "high"
        category = "behavior"

    strings:
        // Code injection chain: allocate + write + execute
        $inject1 = "VirtualAlloc" ascii
        $inject2 = "WriteProcessMemory" ascii
        $inject3 = "CreateRemoteThread" ascii
        // OR: suspicious memory pattern with obfuscation context
        $alloc_suspicious = "VirtualProtect" ascii
        $obfuscate = "GetModuleHandle" ascii
        $peb_walk = "ImageBase" ascii

    condition:
        // Strong signal: actual code injection chain (VirtualAlloc + WriteProcessMemory + CreateRemoteThread)
        (all of ($inject1, $inject2, $inject3)) 
        // OR: memory protection change + explicit code reference
        or ($alloc_suspicious and $obfuscate and $peb_walk)
}

rule Persistence_Mechanisms
{
    meta:
        author = "Malware Analysis"
        description = "Detects persistence installation methods"
        severity = "critical"
        category = "behavior"

    strings:
        $s1 = "HKEY_LOCAL_MACHINE" ascii wide
        $s2 = "\\Run" ascii wide
        $s3 = "\\RunOnce" ascii wide
        $s4 = "Startup" ascii wide
        $s5 = ".exe" ascii
        $copy = /Copy.*system32/ nocase ascii wide

    condition:
        3 of ($s1,$s2,$s3,$s4) and ($copy or $s5)
}

rule C2_Communication
{
    meta:
        author = "Malware Analysis"
        description = "Detects C2/botnet communication patterns with legitimate vendor exclusion"
        severity = "critical"
        category = "behavior"

    strings:
        $s1 = "c2" nocase ascii
        $s2 = "botnet" nocase ascii
        $s3 = "beacon" nocase ascii
        $s4 = "callback" nocase ascii
        $http = /http[s]?:\/\/[a-zA-Z0-9\.-]+[a-zA-Z0-9]/ ascii wide
        
        // Legitimate domains to EXCLUDE
        $microsoft = /microsoft\.(com|org|windows|net)/i ascii wide
        $windows = "windows.com" nocase ascii wide
        $google = "google.com" nocase ascii wide
        $apple = "apple.com" nocase ascii wide
        $github = "github.com" nocase ascii wide
        $azure = "azure.microsoft.com" nocase ascii wide
        $cdn = /cdn\.(microsoft|apple|google)/ ascii wide
        $pdb = ".pdb" ascii  // Debug symbols (PDB paths are normal)

    condition:
        // Require EXPLICIT C2 keywords + domain pattern, excluding known vendors
        ((($s1 or $s2 or $s3 or $s4) and $http) 
        and not any of ($microsoft, $windows, $google, $apple, $github, $azure, $cdn, $pdb))
}

rule Exfiltration_Indicators
{
    meta:
        author = "Malware Analysis"
        description = "Detects data exfiltration patterns"
        severity = "critical"
        category = "behavior"

    strings:
        $s1 = "exfiltrate" nocase ascii
        $s2 = "steal" nocase ascii
        $s3 = "send" nocase ascii wide
        $s4 = "upload" nocase ascii wide
        $s5 = "data" nocase ascii wide
        $file = /\.txt|\.doc|\.xls|\.zip|\.pdf/ nocase ascii

    condition:
        2 of ($s1,$s2,$s3,$s4,$s5) and $file
}

rule Screen_Capture
{
    meta:
        author = "Malware Analysis"
        description = "Detects screen capture/keylogging capabilities (requires suspicious combination)"
        severity = "high"
        category = "behavior"

    strings:
        // Screen capture chain
        $dc = "GetDC" ascii
        $blt = "BitBlt" ascii
        $compat_dc = "CreateCompatibleDC" ascii
        $compat_bmp = "CreateCompatibleBitmap" ascii
        
        // Keylogger indicators (much more specific than SetWindowsHookEx which is legitimate)
        $hook_msg = "SetWindowsHookEx" ascii
        $keylog = "keylog" nocase ascii
        $hook_codes = /WH_KEYBOARD|WH_MOUSE|WH_GETMESSAGE/ ascii

    condition:
        // Strong signal: Full screenshot chain (DC + BitBlt + compat operations)
        (all of ($dc, $blt, $compat_dc, $compat_bmp))
        // OR: Explicit keylogging keywords + hook API
        or ($keylog and $hook_msg and $hook_codes)
}

rule Privilege_Escalation
{
    meta:
        author = "Malware Analysis"
        description = "Detects privilege escalation attempts (specific to exploitation, not admin utilities)"
        severity = "high"
        category = "behavior"

    strings:
        $exploit = "AdjustTokenPrivileges" ascii  // Strong indicator when used for privesc
        $se_debug = "SeDebugPrivilege" ascii
        $se_impersonate = "SeImpersonatePrivilege" ascii
        $create_process_as_user = "CreateProcessAsUser" ascii
        
        // Combined with suspicious patterns
        $inject_chain = "NtCreateThreadEx" ascii
        $write_memory = "WriteProcessMemory" ascii

    condition:
        // Strong signal: Token manipulation APIs used with code injection
        ($exploit and ($inject_chain or $write_memory))
        // OR: Multiple privilege escalation techniques together
        or (($se_debug or $se_impersonate) and $create_process_as_user)
}

rule Lateral_Movement
{
    meta:
        author = "Malware Analysis"
        description = "Detects lateral movement capabilities"
        severity = "high"
        category = "behavior"

    strings:
        $s1 = "psexec" nocase ascii
        $s2 = "wmic" ascii
        $s3 = "psremoting" nocase ascii wide
        $s4 = "lateral" nocase ascii
        $s5 = "spread" nocase ascii
        $net = "\\\\[a-zA-Z]" ascii wide

    condition:
        2 of them
}

rule Rootkit_Indicators
{
    meta:
        author = "Malware Analysis"
        description = "Detects rootkit installation patterns"
        severity = "critical"
        category = "behavior"

    strings:
        $s1 = "rootkit" nocase ascii
        $s2 = "driver" nocase ascii
        $s3 = ".sys" ascii
        $s4 = "kernel" nocase ascii
        $s5 = "hide" nocase ascii
        $s6 = "hook" nocase ascii

    condition:
        3 of them
}

rule Cryptocurrency_Miner
{
    meta:
        author = "Malware Analysis"
        description = "Detects cryptocurrency mining malware"
        severity = "high"
        category = "behavior"
        family = "CryptoMiner"

    strings:
        $s1 = "stratum" nocase ascii
        $s2 = "bitcoin" nocase ascii wide
        $s3 = "ethereum" nocase ascii wide
        $s4 = "monero" nocase ascii wide
        $s5 = "miner" nocase ascii
        $s6 = "mining" nocase ascii
        $pool = /pool\.mining|stratum\+tcp/ nocase ascii

    condition:
        2 of ($s1,$s2,$s3,$s4,$s5,$s6) or $pool
}

rule Worm_Propagation
{
    meta:
        author = "Malware Analysis"
        description = "Detects worm self-propagation mechanisms"
        severity = "critical"
        category = "behavior"

    strings:
        $s1 = "propagat" nocase ascii
        $s2 = "replicate" nocase ascii
        $s3 = "copy" nocase ascii
        $s4 = "infect" nocase ascii
        $s5 = "spread" nocase ascii
        $net = /NetShare|NetUseAdd|FindFirstFile.*\\\\\*/ ascii wide

    condition:
        2 of ($s1,$s2,$s3,$s4,$s5) and $net
}
