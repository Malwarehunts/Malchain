/*
    MalChain Detection Library — YARA
    Phase: ACTIVATION
    Author: MalChain  |  License: MIT
    Validate with: yara -w <rulefile> <sample>
*/

rule MC_ACT_01_Office_Macro_Executor
{
    meta:
        author = "MalChain"
        technique = "MC-ACT-01 User-Executed Files"
        description = "Office document with auto-exec VBA spawning a shell"
    strings:
        $a1 = "AutoOpen" ascii nocase
        $a2 = "Document_Open" ascii nocase
        $a3 = "Auto_Open" ascii nocase
        $s1 = "Shell(" ascii nocase
        $s2 = "WScript.Shell" ascii nocase
        $s3 = "CreateObject" ascii nocase
    condition:
        1 of ($a*) and 1 of ($s*)
}

rule MC_ACT_02_Obfuscated_Script
{
    meta:
        author = "MalChain"
        technique = "MC-ACT-02 Script-Based Execution"
        description = "Base64/encoded PowerShell or script-based in-memory execution"
    strings:
        $p1 = "FromBase64String" ascii nocase
        $p2 = "-enc" ascii nocase
        $p3 = "IEX" ascii
        $p4 = "Invoke-Expression" ascii nocase
        $p5 = "-w hidden" ascii nocase
        $p6 = "-nop" ascii nocase
    condition:
        2 of them
}

rule MC_ACT_04_DLL_SideLoad_Proxy
{
    meta:
        author = "MalChain"
        technique = "MC-ACT-04 DLL Side-Loading or Hijacking"
        description = "Proxy DLL exporting forwarders plus payload staging APIs"
    strings:
        $e1 = "LoadLibraryA" ascii
        $e2 = "GetProcAddress" ascii
        $f1 = ".dll" ascii nocase
        $a1 = "VirtualProtect" ascii
        $a2 = "CreateThread" ascii
    condition:
        uint16(0) == 0x5A4D and $e1 and $e2 and $f1 and 1 of ($a*)
}

rule MC_ACT_06_Malicious_Browser_Extension
{
    meta:
        author = "MalChain"
        technique = "MC-ACT-06 Browser Extension Execution"
        description = "Extension manifest requesting broad permissions + remote code"
    strings:
        $m = "manifest_version" ascii
        $p1 = "\"<all_urls>\"" ascii
        $p2 = "webRequest" ascii
        $p3 = "tabs" ascii
        $c1 = "eval(" ascii
        $c2 = "chrome.runtime.onMessage" ascii
    condition:
        $m and 1 of ($p*) and 1 of ($c*)
}
