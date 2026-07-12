/*
    MalChain Detection Library — YARA
    Phase: CONCEALMENT
    Author: MalChain  |  License: MIT
    Validate with: yara -w <rulefile> <sample>
*/

rule MC_CON_01_Packed_Executable
{
    meta:
        author = "MalChain"
        technique = "MC-CON-01 Obfuscation & Packing"
        description = "Common runtime packer section names in a PE"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $mpress = ".MPRESS1" ascii
        $aspack = ".aspack" ascii
        $themida = "Themida" ascii nocase
        $petite = ".petite" ascii
    condition:
        uint16(0) == 0x5A4D and 1 of them
}

rule MC_CON_02_Fileless_Reflective_Loader
{
    meta:
        author = "MalChain"
        technique = "MC-CON-02 Fileless Malware Execution"
        description = "In-memory reflective loading / shellcode allocation primitives"
    strings:
        $a1 = "VirtualAlloc" ascii
        $a2 = "VirtualAllocEx" ascii
        $a3 = "RtlMoveMemory" ascii
        $a4 = "CreateThread" ascii
        $a5 = "[Reflection.Assembly]::Load" ascii nocase
        $a6 = "ReflectiveLoader" ascii
    condition:
        3 of them
}

rule MC_CON_03_Security_Tool_Tampering
{
    meta:
        author = "MalChain"
        technique = "MC-CON-03 Security Tool Tampering"
        description = "Commands disabling AV/EDR or adding exclusions"
    strings:
        $a = "Set-MpPreference" ascii nocase
        $b = "DisableRealtimeMonitoring" ascii nocase
        $c = "Add-MpPreference -ExclusionPath" ascii nocase
        $d = "sc stop WinDefend" ascii nocase
        $e = "DisableAntiSpyware" ascii nocase
    condition:
        1 of them
}

rule MC_CON_04_Masquerade_System_Name
{
    meta:
        author = "MalChain"
        technique = "MC-CON-04 Masquerading & Impersonation"
        description = "PE claiming a core Windows original filename but lacking MS company"
    strings:
        $n1 = "svchost.exe" wide ascii nocase
        $n2 = "lsass.exe" wide ascii nocase
        $n3 = "services.exe" wide ascii nocase
        $ms = "Microsoft Corporation" wide ascii
    condition:
        uint16(0) == 0x5A4D and 1 of ($n*) and not $ms
}

rule MC_CON_05_Sandbox_Evasion_Strings
{
    meta:
        author = "MalChain"
        technique = "MC-CON-05 Environment & Sandbox Evasion"
        description = "Anti-VM / anti-analysis artifact strings"
    strings:
        $v1 = "VBoxGuest" ascii nocase
        $v2 = "vmware" ascii nocase
        $v3 = "vmtoolsd" ascii nocase
        $v4 = "SbieDll.dll" ascii nocase
        $v5 = "QEMU" ascii
        $v6 = "IsDebuggerPresent" ascii
        $v7 = "CheckRemoteDebuggerPresent" ascii
    condition:
        3 of them
}

rule MC_CON_06_Process_Injection_Primitives
{
    meta:
        author = "MalChain"
        technique = "MC-CON-06 Process Injection"
        description = "Classic remote-injection / process-hollowing API set"
    strings:
        $a1 = "OpenProcess" ascii
        $a2 = "VirtualAllocEx" ascii
        $a3 = "WriteProcessMemory" ascii
        $a4 = "CreateRemoteThread" ascii
        $a5 = "NtUnmapViewOfSection" ascii
        $a6 = "SetThreadContext" ascii
        $a7 = "QueueUserAPC" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule MC_CON_07_Polymorphic_Loader
{
    meta:
        author = "MalChain"
        technique = "MC-CON-07 Polymorphism & Metamorphism"
        description = "Self-modifying / runtime-decrypting loader primitives"
    strings:
        $a1 = "VirtualProtect" ascii
        $a2 = "WriteProcessMemory" ascii
        $x1 = { 33 ?? 88 ?? ?? 40 }        // xor/store/inc decrypt-loop shape
        $x2 = { 80 34 ?? ?? 40 3B }        // xor byte ptr [reg+key]; inc; cmp
    condition:
        uint16(0) == 0x5A4D and 1 of ($a*) and 1 of ($x*)
}

rule MC_CON_08_Log_Manipulation
{
    meta:
        author = "MalChain"
        technique = "MC-CON-08 Log & Artifact Manipulation"
        description = "Event log clearing / tampering commands"
    strings:
        $a = "wevtutil cl" ascii nocase
        $b = "Clear-EventLog" ascii nocase
        $c = "wevtutil clear-log" ascii nocase
        $d = "Remove-EventLog" ascii nocase
    condition:
        1 of them
}

rule MC_CON_09_LOLBin_Proxy_Execution
{
    meta:
        author = "MalChain"
        technique = "MC-CON-09 Living-off-the-Land for Evasion"
        description = "LOLBin proxy-execution command patterns"
    strings:
        $a = "regsvr32" ascii nocase
        $s = "scrobj.dll" ascii nocase
        $b = "mshta" ascii nocase
        $j = "javascript:" ascii nocase
        $c = "certutil" ascii nocase
        $u = "-urlcache" ascii nocase
    condition:
        ($a and $s) or ($b and $j) or ($c and $u)
}

rule MC_CON_10_AntiForensics_Cleanup
{
    meta:
        author = "MalChain"
        technique = "MC-CON-10 Anti-Forensics & Cleanup"
        description = "Shadow copy deletion / recovery disabling / journal wipe"
    strings:
        $a = "vssadmin delete shadows" ascii nocase
        $b = "wmic shadowcopy delete" ascii nocase
        $c = "wbadmin delete catalog" ascii nocase
        $d = "fsutil usn deletejournal" ascii nocase
        $e = "recoveryenabled no" ascii nocase
    condition:
        1 of them
}
