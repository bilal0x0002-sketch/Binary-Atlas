rule Suspicious_APIs
{
    meta:
        author = "MaxPayne"
        description = "Detects suspicious API combinations commonly used in malware"
        severity = "medium"

    strings:
        $inject1 = "VirtualAlloc" ascii
        $inject2 = "WriteProcessMemory" ascii
        $inject3 = "CreateRemoteThread" ascii
        $encrypt1 = "CryptEncrypt" ascii
        $encrypt2 = "CryptDecrypt" ascii
        $exec = "WinExec" ascii
        $hide = "SetWindowsHookEx" ascii

    condition:
        ($inject1 and $inject2 and $inject3) or ($encrypt1 and $encrypt2) or ($exec and $hide)
}
