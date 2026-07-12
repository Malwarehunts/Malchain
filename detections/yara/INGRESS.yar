/*
    MalChain Detection Library — YARA
    Phase: INGRESS
    Author: MalChain  |  License: MIT
    Validate with: yara -w <rulefile> <sample>
*/

rule MC_ING_01_Removable_Media_Autorun
{
    meta:
        author = "MalChain"
        technique = "MC-ING-01 Removable Media & File Transfer"
        description = "Autorun.inf abusing removable media to auto-launch a payload"
    strings:
        $a = "[autorun]" ascii nocase
        $b = "open=" ascii nocase
        $c = "shellexecute=" ascii nocase
        $d = "shell\\open\\command" ascii nocase
        $exe = ".exe" ascii nocase
    condition:
        $a and 1 of ($b,$c,$d) and $exe
}

rule MC_ING_02_Malvertising_HTA_Dropper
{
    meta:
        author = "MalChain"
        technique = "MC-ING-02 Malvertising & Drive-By Downloads"
        description = "HTA/JS drive-by dropper invoking script hosts or downloads"
    strings:
        $hta = "<hta:application" ascii nocase
        $ws  = "WScript.Shell" ascii nocase
        $ado = "ADODB.Stream" ascii nocase
        $xhr = "MSXML2.XMLHTTP" ascii nocase
        $ps  = "powershell" ascii nocase
    condition:
        ($hta or $ws) and 2 of ($ado,$xhr,$ps)
}

rule MC_ING_03_Supply_Chain_Installer_Backdoor
{
    meta:
        author = "MalChain"
        technique = "MC-ING-03 Supply Chain Compromise"
        description = "Installer/updater carrying embedded shell or download logic"
    strings:
        $u1 = "cmd.exe /c" ascii nocase
        $u2 = "powershell -" ascii nocase
        $u3 = "DownloadString" ascii nocase
        $u4 = "certutil -urlcache" ascii nocase
        $msi = "Windows Installer" ascii nocase
    condition:
        $msi and 2 of ($u1,$u2,$u3,$u4)
}

rule MC_ING_05_BadUSB_HID_Payload
{
    meta:
        author = "MalChain"
        technique = "MC-ING-05 Malicious or Compromised USB Devices"
        description = "Rubber Ducky / BadUSB keystroke-injection script artifacts"
    strings:
        $d1 = "DELAY " ascii
        $d2 = "STRING " ascii
        $d3 = "GUI r" ascii
        $d4 = "ENTER" ascii
        $d5 = "duckyscript" ascii nocase
    condition:
        $d5 or (3 of ($d1,$d2,$d3,$d4))
}

rule MC_ING_06_Watering_Hole_Injected_Script
{
    meta:
        author = "MalChain"
        technique = "MC-ING-06 Watering Hole Attacks"
        description = "Obfuscated JS injected into web content for selective delivery"
    strings:
        $s1 = "eval(" ascii
        $s2 = "String.fromCharCode(" ascii
        $s3 = "unescape(" ascii
        $s4 = "document.write(" ascii
        $s5 = "atob(" ascii
    condition:
        3 of them
}
