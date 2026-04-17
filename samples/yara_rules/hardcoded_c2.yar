rule Hardcoded_C2
{
    meta:
        author = "MaxPayne"
        description = "Detects hardcoded IPs in PE"
        severity = "high"

    strings:
        $ip1 = "127.0.0.1" ascii
        $ip2 = "192.168.1.1" ascii
        $ip3 = "10.0.0.1" ascii

    condition:
        any of ($ip*)
}
