/*
    MalChain Detection Library — YARA
    Phase: EXTRACTION
    Author: MalChain  |  License: MIT
    Validate with: yara -w <rulefile> <sample>
*/

rule MC_EXT_02_DNS_Tunnel_Tooling
{
    meta:
        author = "MalChain"
        technique = "MC-EXT-02 DNS Tunneling"
        description = "Known DNS-tunnel tool markers / DNS TXT exfil routines"
    strings:
        $a = "iodine" ascii nocase
        $b = "dnscat" ascii nocase
        $c = "dns2tcp" ascii nocase
        $t = "DNS_TYPE_TXT" ascii
        $q = "DnsQuery_A" ascii
    condition:
        1 of ($a,$b,$c) or ($t and $q)
}

rule MC_EXT_04_Messaging_Channel_Exfil
{
    meta:
        author = "MalChain"
        technique = "MC-EXT-04 Messaging and Social Platform Channels"
        description = "Hardcoded Telegram/Discord webhook exfil endpoints"
    strings:
        $a = "api.telegram.org/bot" ascii nocase
        $b = "discord.com/api/webhooks" ascii nocase
        $c = "discordapp.com/api/webhooks" ascii nocase
        $d = "hooks.slack.com/services" ascii nocase
    condition:
        1 of them
}

rule MC_EXT_06_Tor_Anonymizer_Artifacts
{
    meta:
        author = "MalChain"
        technique = "MC-EXT-06 Tor / Proxy / VPN Anonymization Channels"
        description = "Embedded Tor / onion routing artifacts"
    strings:
        $a = ".onion" ascii nocase
        $b = "tor.exe" ascii nocase
        $c = "obfs4proxy" ascii nocase
        $d = "SOCKS5" ascii
        $e = "torrc" ascii nocase
    condition:
        2 of them
}

rule MC_EXT_07_Encrypted_C2_Config
{
    meta:
        author = "MalChain"
        technique = "MC-EXT-07 Encrypted Command-and-Control Channels"
        description = "Beacon/C2 config primitives and known malleable markers"
    strings:
        $a = "User-Agent:" ascii
        $b = "WinHttpConnect" ascii
        $c = "InternetOpenA" ascii
        $bk = "beacon.dll" ascii nocase
        $mz = "ReflectiveLoader" ascii
    condition:
        uint16(0) == 0x5A4D and ($bk or $mz or (2 of ($a,$b,$c)))
}

rule MC_EXT_09_Steganography_Tooling
{
    meta:
        author = "MalChain"
        technique = "MC-EXT-09 Steganographic Data Transfer"
        description = "Steganography tools / PS image-embedding routines"
    strings:
        $a = "steghide" ascii nocase
        $b = "OpenStego" ascii nocase
        $c = "Invoke-PSImage" ascii nocase
        $d = "outguess" ascii nocase
    condition:
        1 of ($a,$b,$c,$d)
}
