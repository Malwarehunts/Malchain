/*
    MalChain Detection Library — YARA
    Phase: ANCHORING
    Author: MalChain  |  License: MIT
    Validate with: yara -w <rulefile> <sample>
*/

rule MC_ANC_06_WMI_Event_Consumer
{
    meta:
        author = "MalChain"
        technique = "MC-ANC-06 WMI & Event Subscription Persistence"
        description = "Script creating permanent WMI event subscription persistence"
    strings:
        $a = "__EventFilter" ascii nocase
        $b = "CommandLineEventConsumer" ascii nocase
        $c = "ActiveScriptEventConsumer" ascii nocase
        $d = "__FilterToConsumerBinding" ascii nocase
        $e = "root\\subscription" ascii nocase
    condition:
        2 of them
}

rule MC_ANC_07_Fileless_Registry_Payload_Loader
{
    meta:
        author = "MalChain"
        technique = "MC-ANC-07 Fileless & In-Memory Persistence"
        description = "Loader reading an encoded payload from the registry into memory"
    strings:
        $r1 = "Get-ItemProperty" ascii nocase
        $r2 = "RegOpenKeyEx" ascii
        $b1 = "FromBase64String" ascii nocase
        $m1 = "VirtualAlloc" ascii
        $m2 = "[Reflection.Assembly]::Load" ascii nocase
    condition:
        (1 of ($r*)) and $b1 and (1 of ($m*))
}
