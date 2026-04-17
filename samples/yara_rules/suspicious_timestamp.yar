rule Suspicious_Timestamp
{
    meta:
        author = "MaxPayne"
        description = "Detects PE files with zeroed or obviously fake compilation timestamps"
        severity = "medium"

    strings:
        $zero_ts = { 00 00 00 00 }  // Unix epoch zero (Jan 1, 1970) - likely tampered
        $epoch_marker = "19700101" ascii  // Epoch date marker

    condition:
        all of them
}
