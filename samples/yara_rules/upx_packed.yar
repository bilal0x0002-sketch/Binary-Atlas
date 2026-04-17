rule UPX_Packer
{
    meta:
        author = "MaxPayne"
        description = "Detects UPX packed PE sections"
        severity = "high"

    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii

    condition:
        any of ($upx0, $upx1)
}
