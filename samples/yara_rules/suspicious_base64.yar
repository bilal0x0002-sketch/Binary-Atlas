rule Suspicious_Base64
{
    meta:
        author = "MaxPayne"
        description = "Detects suspicious Base64 encoded patterns combined with keywords"
        severity = "medium"

    strings:
        $b64_long = /[A-Za-z0-9+\/=]{100,}/
        $keyword1 = "aHR0cDovL" ascii  // http:// in base64
        $keyword2 = "gMjAvLw" ascii    // // in base64
        $keyword3 = "TXV0ZXg" ascii    // Mutex in base64
        $keyword4 = "Y21kLmV" ascii    // cmd.exe in base64
        $keyword5 = "cG93ZXJzaGVsbA" ascii  // powershell in base64

    condition:
        ($b64_long and any of ($keyword*)) or (4 of ($keyword*))
}
