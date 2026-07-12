/*
    MalChain Detection Library — YARA
    Phase: EXPANSION
    Author: MalChain  |  License: MIT
    Validate with: yara -w <rulefile> <sample>
*/

rule MC_EXP_03_Credential_Ticket_Tooling
{
    meta:
        author = "MalChain"
        technique = "MC-EXP-03 Pass-the-Hash / Pass-the-Ticket"
        description = "Mimikatz/Rubeus PtH/PtT command artifacts"
    strings:
        $a = "sekurlsa::pth" ascii nocase
        $b = "sekurlsa::logonpasswords" ascii nocase
        $c = "kerberos::ptt" ascii nocase
        $d = "asktgt" ascii nocase
        $e = "Rubeus" ascii
    condition:
        1 of them
}

rule MC_EXP_06_Worm_SelfPropagation
{
    meta:
        author = "MalChain"
        technique = "MC-EXP-06 Worm-like Self-Propagation"
        description = "Self-copy to network shares / removable drives via enumeration"
    strings:
        $a1 = "WNetAddConnection2" ascii
        $a2 = "GetLogicalDrives" ascii
        $a3 = "CopyFile" ascii
        $s1 = "\\ADMIN$" ascii nocase
        $s2 = "\\C$" ascii nocase
        $s3 = "autorun.inf" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($a*) and 1 of ($s*)
}

rule MC_EXP_08_Kerberos_Trust_Abuse
{
    meta:
        author = "MalChain"
        technique = "MC-EXP-08 Identity & Trust Relationship Abuse"
        description = "Golden/silver ticket and delegation abuse artifacts"
    strings:
        $a = "kerberos::golden" ascii nocase
        $b = "kerberos::silver" ascii nocase
        $c = "/krbtgt" ascii nocase
        $d = "s4u" ascii nocase
        $e = "/impersonateuser" ascii nocase
    condition:
        1 of them
}

rule MC_EXP_09_DCSync_Directory_Attack
{
    meta:
        author = "MalChain"
        technique = "MC-EXP-09 Directory Services Targeting"
        description = "DCSync / directory replication abuse artifacts"
    strings:
        $a = "lsadump::dcsync" ascii nocase
        $b = "GetNCChanges" ascii
        $c = "DsGetNCChanges" ascii
        $d = "Get-ADReplAccount" ascii nocase
    condition:
        1 of them
}
