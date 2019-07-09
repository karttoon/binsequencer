## binsequencer (rid?l?r)

### [+] INTRO [+]

Binsequencer is intended to scan a corpus of similar malware (family/campaign/like-tools) and build a YARA rule that will detect similar sections of code.

Specifically, each file will be analyzed and have their data abstracted into sequences of x86 instruction sets. These sets are then used in a sliding window to find commonality across the entire sample corpus. Upon finding an acceptable match, the application will attempt various methods of techniques to create a YARA match moving most specific to least. In the least specific matching, it will convert the matched instruction sets into a series of x86 opcodes, surrounded by wildcards, for usage in a YARA rule.

There are a couple of options to adjust the minimum length of the instruction set, but 25 has proven to be fairly reliable while testing samples. If you go too low, you'll start matching more samples that may be unrelated. You can also choose how many matches you want to use for your YARA rule and the application will attempt to find unique instruction sets. Additionally, while the script is intended to be run on x86 PE files, you can instruct it to run on non-PE (JAR/PDF/etc) files or just individual files (shellcode). Results may vary significantly if it fails opcode matching as the bytes may not actually be opcodes - YMMV.

Note that a match does not imply maliciousness and a match does not imply it's relevant to your samples (could be shared code, similar programing style, common compiler, or just the same bytes). 

```
usage: binsequencer.py [-h] [-c <integer_percent>] [-m <integer>]
                       [-l <integer>] [-v] [-a {x86,x64}] [-g <file>] [-d]
                       [-Q] [-n] [-o] [-s]
                       ...

Sequence a set of binaries to identify commonalities in code structure.

positional arguments:
  file

optional arguments:
  -h, --help            show this help message and exit
  -c <integer_percent>, --commonality <integer_percent>
                        Commonality percentage the sets criteria for matches,
                        default 100
  -m <integer>, --matches <integer>
                        Set the minimum number of matches to find, default 1
  -l <integer>, --length <integer>
                        Set the minimum length of the instruction set, default
                        25
  -v, --verbose         Prints data while processing, use only for debugging
  -a {x86,x64}, --arch {x86,x64}
                        Select code architecture of samples, default x86
  -g <file>, --gold <file>
                        Override gold selection
  -d, --default         Accept default prompt values
  -Q, --quiet           Disable output except for YARA rule
  -n, --nonpe           Process non-PE files (eg PCAP/JAR/PDF/DOC)
  -o, --opcode          Use only the opcode matching technique
  -s, --strings         Include strings in YARA for matched hashes
```

Quick links to examples:
* [Basic Usage - APT1](#basic_usage)
* [Non-PE w/ Strings](#non_pe)

### [+] EXAMPLES [+]

##### basic_usage

```
$ python binsequencer.py APT1_Malware/

[+] Extracting instructions and generating sets

	[-]APT1_Malware/0050e14f8e6bca0b2b99708f0659e38f407debec5ab7afc71de48fb104508a60
		.text - 2978 instructions extracted
	[-]APT1_Malware/04a23b3cb2d6361df66ca94a470ffa1017a8e5cd3255ce342219765d7d4619bc
		.text - 2980 instructions extracted
<TRUNCATED>
	[-]APT1_Malware/f737829e9ad9a025945ad9ce803641677ae0fe3abf43b1984a7c8ab994923178
		.text - 4574 instructions extracted
	[-]APT1_Malware/fc2751ff381d75154c76da7a42211509f7cc3fd4b50956e36e53b4f7653534d5
		.text - 1907 instructions extracted

[+] Golden hash (1907 instructions) - APT1_Malware/64a373487c4cc2b8b60687ecc01150b546b18be7069981c5fe5d48075190f1ff

[+] Zeroing in longest mnemonic instruction set in .text

	[-] Matches - 0     Block Size - 1907  Time - 0.00 seconds
	[-] Matches - 0     Block Size - 954   Time - 0.06 seconds
	[-] Matches - 0     Block Size - 478   Time - 0.07 seconds
	[-] Matches - 120   Block Size - 240   Time - 0.11 seconds
	[-] Matches - 1     Block Size - 359   Time - 0.07 seconds
	[-] Matches - 0     Block Size - 418   Time - 0.07 seconds
	[-] Matches - 0     Block Size - 389   Time - 0.07 seconds
	[-] Matches - 0     Block Size - 375   Time - 0.07 seconds
	[-] Matches - 0     Block Size - 368   Time - 0.07 seconds
	[-] Matches - 0     Block Size - 365   Time - 0.07 seconds
	[-] Matches - 0     Block Size - 363   Time - 0.07 seconds
	[-] Matches - 0     Block Size - 362   Time - 0.07 seconds
	[-] Matches - 0     Block Size - 361   Time - 0.07 seconds
	[-] Matches - 0     Block Size - 360   Time - 0.07 seconds
	[-] Matches - 1     Block Size - 359   Time - 0.07 seconds
	[-] Matches - 0     Block Size - 360   Time - 0.08 seconds

	[-] Moving 1 instruction sets to review with a length of 359

    [*] Do you want to display matched instruction set? [Y/N] y

	push|push|push|mov|mov|mov|xor|cdq|idiv|cmp|jne|mov|jmp|cmp|jne|lea|jmp|cmp|lea|je|mov|lea|mov|imul|mov|mov|shr|add|dec|cmp|jge|pop|xor|pop|pop|ret|push|lea|push|push|mov|mov|call|mov|mov|mov|mov|mov|add|shr|rep movsd|mov|and|rep movsb|mov|mov|cmp|mov|jl|mov|mul|shr|lea|sub|mov|mov|add|mov|add|sar|and|mov|mov|mov|mov|mov|and|sar|shl|and|or|mov|mov|mov|mov|sar|and|and|shl|or|mov|mov|mov|and|dec|mov|mov|jne|mov|cmp|jne|mov|mov|lea|sar|and|mov|mov|mov|mov|and|sar|shl|and|or|mov|mov|mov|and|mov|mov|mov|jmp|cmp|jne|mov|mov|sar|and|mov|mov|mov|and|shl|mov|mov|mov|mov|mov|add|push|mov|call|add|mov|pop|pop|pop|pop|pop|ret|nop|nop|nop|nop|nop|nop|nop|nop|nop|nop|push|push|mov|push|mov|or|xor|repne scasb|not|dec|mov|mov|and|jns|dec|or|inc|je|pop|pop|xor|pop|ret|push|push|xor|call|add|test|je|mov|jmp|push|push|call|add|test|je|mov|lea|cdq|and|add|mov|mov|sar|sub|cmp|jge|pop|pop|xor|pop|ret|sub|push|mov|push|xor|xor|call|mov|mov|add|cmp|jl|mov|shr|mov|neg|lea|mov|movsx|push|push|call|mov|sub|shl|mov|movsx|push|push|call|mov|sub|mov|sar|or|shl|mov|mov|movsx|push|push|call|mov|sub|mov|sar|or|shl|mov|mov|movsx|push|push|call|mov|sub|or|mov|mov|add|add|add|dec|mov|jne|mov|cmp|jne|movsx|push|push|call|mov|sub|shl|mov|movsx|push|push|call|mov|sub|mov|sar|or|shl|mov|mov|movsx|push|push|call|mov|sub|sar|or|add|mov|add|jmp|cmp|jne|movsx|push|push|call|mov|sub|shl|mov|movsx|push|push|call|mov|sub|sar|or|add|mov|inc|mov|mov|mov|mov|shr|rep movsd|mov|push|and|rep movsb|call|add|mov|pop|pop|pop|pop|ret|nop|nop|nop|nop|nop

    [*] Do you want to disassemble the underlying bytes? [Y/N] y

	0x10001000:	push       ecx                                      | 51
	0x10001001:	push       ebx                                      | 53
<TRUNCATED>
	0x10001409:	nop                                                 | 90
	0x1000140a:	nop                                                 | 90

    [*] Do you want to display the raw byte blob? [Y/N] y

	5153568B742414B9030000008BC633DB99F7F93BD375048BC6EB1683FA0175058D4602EB0C83FA028D460174048B4424088D0C8500000000B856555555F7E98B4C241C8BC2C1E81F03D0493BCA7D065E33C05B59C3558D5601575289742414895C2428E8EE1100008BCE8B74241C8BE88BC18BFD83C404C1E902F3A58BC883E103F3A48B4C241C8B74242083F903C60429000F8C87000000B8ABAAAAAAF7E1D1EA8D04522BC8894C24108B7C242483C3048A0C2F83C703C1F90283E13F897C24248A811040001088441EFC8A4C2FFD8A442FFE83E103C1F804C1E10483E00F0BC88A8910400010884C1EFD8A442FFF8A4C2FFEC1F80683E10F83E003C1E1020BC18A801040001088441EFE8A4C2FFF83E13F4A8A811040001088441EFF758B8B44241083F802754E8B4424248A0C288D7C2801C1F90283E13F8A91104000108814338A04288A0F83E003C1F904C1E00483E10F0BC18A9010400010885433018A0783E00F8A0C8510400010884C3302C64433033DEB3883F80175368B4424248A1428C1FA0283E23F8A8A10400010880C338A142883E203C1E2048A821040001088443301B03D884433028844330383C30455C6043300E89510000083C4048BC35F5D5E5B59C39090909090909090909053568B74240C578BFE83C9FF33C0F2AEF7D1498BF98BC7250300008079054883C8FC4074065F5E33C05BC368544000105633DBFF153430001083C40885C07407BB02000000EB156A3D56FF153030001083C40885C07405BB010000008D047F9983E20303C28BC88B442418C1F9022BCB3BC17D065F5E33C05BC32BFB55897C24145033FF33DBE8FB0F00008BE88B44241883C40483F8040F8CBD0000008BC8C1E902894C241CF7D98D1488895424140FBE043E506810400010FF1530300010B9104000102AC1C0E00288042B0FBE543E015251FF15303000108A142B2D104000108BC8C1F9040AD1C0E00488142B88442B010FBE543E02526810400010FF15303000108A542B012D104000108BC8C1F9020AD1C0E00688542B0188442B020FBE543E03526810400010FF15303000108A4C2B022D104000100AC88B44243C884C2B0283C42083C70483C303488944241C0F8559FFFFFF8B44241483F803756E0FBE0437506810400010FF1530300010B9104000102AC1C0E00288042B0FBE5437015251FF15303000108A142B2D104000108BC8C1F9040AD1C0E00488142B88442B010FBE543702526810400010FF15303000108A4C2B012D10400010C1F8020AC883C418884C2B0183C302EB4383F802753E0FBE0437506810400010FF1530300010B9104000102AC1C0E00288042B0FBE5437015251FF15303000108A0C2B2D10400010C1F8040AC883C410880C2B438B7C24188BCB8BC18BF5C1E902F3A58BC85583E103F3A4E8540E000083C4048BC35D5F5E5BC39090909090

    [*] Do you want to keep this set? [Y/N] y

[+] Keeping 1 mnemonic set using 100 % commonality out of 48 hashes

	[-] Length - 359   Section - .text

[+] Printing offsets of type: longest

	[-] Gold matches

	----------v SET rule0 v----------
	push|push|push|mov|mov|mov|xor|cdq|idiv|cmp|jne|mov|jmp|cmp|jne|lea|jmp|cmp|lea|je|mov|lea|mov|imul|mov|mov|shr|add|dec|cmp|jge|pop|xor|pop|pop|ret|push|lea|push|push|mov|mov|call|mov|mov|mov|mov|mov|add|shr|rep movsd|mov|and|rep movsb|mov|mov|cmp|mov|jl|mov|mul|shr|lea|sub|mov|mov|add|mov|add|sar|and|mov|mov|mov|mov|mov|and|sar|shl|and|or|mov|mov|mov|mov|sar|and|and|shl|or|mov|mov|mov|and|dec|mov|mov|jne|mov|cmp|jne|mov|mov|lea|sar|and|mov|mov|mov|mov|and|sar|shl|and|or|mov|mov|mov|and|mov|mov|mov|jmp|cmp|jne|mov|mov|sar|and|mov|mov|mov|and|shl|mov|mov|mov|mov|mov|add|push|mov|call|add|mov|pop|pop|pop|pop|pop|ret|nop|nop|nop|nop|nop|nop|nop|nop|nop|nop|push|push|mov|push|mov|or|xor|repne scasb|not|dec|mov|mov|and|jns|dec|or|inc|je|pop|pop|xor|pop|ret|push|push|xor|call|add|test|je|mov|jmp|push|push|call|add|test|je|mov|lea|cdq|and|add|mov|mov|sar|sub|cmp|jge|pop|pop|xor|pop|ret|sub|push|mov|push|xor|xor|call|mov|mov|add|cmp|jl|mov|shr|mov|neg|lea|mov|movsx|push|push|call|mov|sub|shl|mov|movsx|push|push|call|mov|sub|mov|sar|or|shl|mov|mov|movsx|push|push|call|mov|sub|mov|sar|or|shl|mov|mov|movsx|push|push|call|mov|sub|or|mov|mov|add|add|add|dec|mov|jne|mov|cmp|jne|movsx|push|push|call|mov|sub|shl|mov|movsx|push|push|call|mov|sub|mov|sar|or|shl|mov|mov|movsx|push|push|call|mov|sub|sar|or|add|mov|add|jmp|cmp|jne|movsx|push|push|call|mov|sub|shl|mov|movsx|push|push|call|mov|sub|sar|or|add|mov|inc|mov|mov|mov|mov|shr|rep movsd|mov|push|and|rep movsb|call|add|mov|pop|pop|pop|pop|ret|nop|nop|nop|nop|nop
	----------^ SET rule0 ^-----------

		APT1_Malware/64a373487c4cc2b8b60687ecc01150b546b18be7069981c5fe5d48075190f1ff                        0x10001000 - 0x1000140a in .text

	[-] Remaining matches

	----------v SET rule0 v----------
		APT1_Malware/0050e14f8e6bca0b2b99708f0659e38f407debec5ab7afc71de48fb104508a60                        0x10001000 - 0x1000140a in .text
		APT1_Malware/04a23b3cb2d6361df66ca94a470ffa1017a8e5cd3255ce342219765d7d4619bc                        0x10001000 - 0x1000140a in .text
<TRUNCATED>
		APT1_Malware/f737829e9ad9a025945ad9ce803641677ae0fe3abf43b1984a7c8ab994923178                        0x10001700 - 0x10001aff in .text
		APT1_Malware/fc2751ff381d75154c76da7a42211509f7cc3fd4b50956e36e53b4f7653534d5                        0x10001000 - 0x1000140a in .text
	----------^ SET rule0 ^-----------

[+] Generating YARA rule for matches off of bytes from gold - APT1_Malware/64a373487c4cc2b8b60687ecc01150b546b18be7069981c5fe5d48075190f1ff

    [*] Do you want to try and morph rule0 for accuracy and attempt to make it VT Retro friendly [Y/N] y

[+] Check 01 - Checking for exact byte match

[+] Check 02 - Checking for optimal opcode match

[+] Check 03 - Dynamically morphing YARA rule0
	[*] Dynamic morphing succeeded

    [*] Do you want to include matched sample names in rule meta? [Y/N] y

    [*] Do you want to include matched byte sequence in rule comments? [Y/N] y

[+] Completed YARA rules

/*

SAMPLES:

APT1_Malware/e9d191e5a9565068627795d74eb6605f3878b6c5655955f72f69dffa5076e495
APT1_Malware/f48db6b5d9d34ead2dc736cd7f8af15b7b6fb3e39fe0baf5eac52e1e3967795c
<TRUNCATED>
APT1_Malware/4f0532e15ced95a1cebc13dd268dcbe7c609d4da237d9e46916678f288d3d9c6
APT1_Malware/383f0d2cbf8914c3ecb23ea82bff38e1c048980806e37d75e3539362d105675c

BYTES:

5153568B742414B9030000008BC633DB99F7F93BD375048BC6EB1683FA0175058D4602EB0C83FA028D460174048B4424088D0C8500000000B856555555F7E98B4C241C8BC2C1E81F03D0493BCA7D065E33C05B59C3558D5601575289742414895C2428E8EE1100008BCE8B74241C8BE88BC18BFD83C404C1E902F3A58BC883E103F3A48B4C241C8B74242083F903C60429000F8C87000000B8ABAAAAAAF7E1D1EA8D04522BC8894C24108B7C242483C3048A0C2F83C703C1F90283E13F897C24248A811040001088441EFC8A4C2FFD8A442FFE83E103C1F804C1E10483E00F0BC88A8910400010884C1EFD8A442FFF8A4C2FFEC1F80683E10F83E003C1E1020BC18A801040001088441EFE8A4C2FFF83E13F4A8A811040001088441EFF758B8B44241083F802754E8B4424248A0C288D7C2801C1F90283E13F8A91104000108814338A04288A0F83E003C1F904C1E00483E10F0BC18A9010400010885433018A0783E00F8A0C8510400010884C3302C64433033DEB3883F80175368B4424248A1428C1FA0283E23F8A8A10400010880C338A142883E203C1E2048A821040001088443301B03D884433028844330383C30455C6043300E89510000083C4048BC35F5D5E5B59C39090909090909090909053568B74240C578BFE83C9FF33C0F2AEF7D1498BF98BC7250300008079054883C8FC4074065F5E33C05BC368544000105633DBFF153430001083C40885C07407BB02000000EB156A3D56FF153030001083C40885C07405BB010000008D047F9983E20303C28BC88B442418C1F9022BCB3BC17D065F5E33C05BC32BFB55897C24145033FF33DBE8FB0F00008BE88B44241883C40483F8040F8CBD0000008BC8C1E902894C241CF7D98D1488895424140FBE043E506810400010FF1530300010B9104000102AC1C0E00288042B0FBE543E015251FF15303000108A142B2D104000108BC8C1F9040AD1C0E00488142B88442B010FBE543E02526810400010FF15303000108A542B012D104000108BC8C1F9020AD1C0E00688542B0188442B020FBE543E03526810400010FF15303000108A4C2B022D104000100AC88B44243C884C2B0283C42083C70483C303488944241C0F8559FFFFFF8B44241483F803756E0FBE0437506810400010FF1530300010B9104000102AC1C0E00288042B0FBE5437015251FF15303000108A142B2D104000108BC8C1F9040AD1C0E00488142B88442B010FBE543702526810400010FF15303000108A4C2B012D10400010C1F8020AC883C418884C2B0183C302EB4383F802753E0FBE0437506810400010FF1530300010B9104000102AC1C0E00288042B0FBE5437015251FF15303000108A0C2B2D10400010C1F8040AC883C410880C2B438B7C24188BCB8BC18BF5C1E902F3A58BC85583E103F3A4E8540E000083C4048BC35D5F5E5BC39090909090

INFO:

binsequencer.py APT1_Malware/
Match SUCCESS for morphing

*/

rule rule0
    {
        meta:
            description = "Autogenerated by Binsequencer v.1.0.4 from APT1_Malware/64a373487c4cc2b8b60687ecc01150b546b18be7069981c5fe5d48075190f1ff"
            author      = ""
            date        = "2017-11-28"

        strings:
            $rule0_bytes = { 5153568B??????B9????????8B??33??99F7??3B??75??8B??EB??83????75??8D????EB??83????8D????74??8B??????8D????????????B8????????F7??8B??????8B??C1????03??493B??7D??5E33??5B59C3558D????575289??????89??????E8????????8B??8B??????8B??8B??8B??83????C1????F3A58B??83????F3A48B??????8B??????83????C6??????0F8C????????B8????????F7??D1??8D????2B??89??????8B??????83????8A????83????C1????83????89??????8A??????????88??????8A??????8A??????83????C1????C1????83????0B??8A??????????88??????8A??????8A??????C1????83????83????C1????0B??8A??????????88??????8A??????83????4A8A??????????88??????75??8B??????83????75??8B??????8A????8D??????C1????83????8A??????????88????8A????8A??83????C1????C1????83????0B??8A??????????88??????8A??83????8A????????????88??????C6????????EB??83????75??8B??????8A????C1????83????8A??????????88????8A????83????C1????8A??????????88??????B0??88??????88??????83????55C6??????E8????????83????8B??5F5D5E5B59C39090909090909090909053568B??????578B??83????33??F2AEF7??498B??8B??25????????79??4883????4074??5F5E33??5BC368????????5633??(E8|FF)[4-6]83????85??74??BB????????EB??6A??56(E8|FF)[4-6]83????85??74??BB????????8D????9983????03??8B??8B??????C1????2B??3B??7D??5F5E33??5BC32B??5589??????5033??33??E8????????8B??8B??????83????83????0F8C????????8B??C1????89??????F7??8D????89??????0FBE????5068????????(E8|FF)[4-6]B9????????2A??C0????88????0FBE??????5251(E8|FF)[4-6]8A????2D????????8B??C1????0A??C0????88????88??????0FBE??????5268????????(E8|FF)[4-6]8A??????2D????????8B??C1????0A??C0????88??????88??????0FBE??????5268????????(E8|FF)[4-6]8A??????2D????????0A??8B??????88??????83????83????83????4889??????0F85????????8B??????83????75??0FBE????5068????????(E8|FF)[4-6]B9????????2A??C0????88????0FBE??????5251(E8|FF)[4-6]8A????2D????????8B??C1????0A??C0????88????88??????0FBE??????5268????????(E8|FF)[4-6]8A??????2D????????C1????0A??83????88??????83????EB??83????75??0FBE????5068????????(E8|FF)[4-6]B9????????2A??C0????88????0FBE??????5251(E8|FF)[4-6]8A????2D????????C1????0A??83????88????438B??????8B??8B??8B??C1????F3A58B??5583????F3A4E8????????83????8B??5D5F5E5BC39090909090 }

        condition:
            all of them
}
```

##### non_pe

```
$ python binsequencer.py -n -d -s ShellCode/cobaltstrike.bin

[+] Extracting instructions and generating sets

	[-]ShellCode/cobaltstrike.bin
		nonpefile - 524 instructions extracted

[+] Golden hash (524 instructions) - ShellCode/cobaltstrike.bin

[+] Zeroing in longest mnemonic instruction set in nonpefile

	[-] Moving 1 instruction sets to review with a length of 524

[+] Keeping 1 mnemonic set using 100 % commonality out of 1 hashes

	[-] Length - 524   Section - nonpefile

[+] Printing offsets of type: longest

	[-] Gold matches

	----------v SET rule0 v----------
	jmp|int3|int3|int3|dec|mov|dec|mov|push|dec|sub|dec|mov|mov|dec|mov|dec|mov|dec|mov|dec|test|je|inc|movups|dec|arpl|xor|dec|mov|movdqu|inc|mov|test|je|dec|mov|dec|shr|inc|movzx|inc|test|je|dec|mov|inc|mov|movsx|ror|cmp|jl|add|add|dec|inc|dec|sub|jne|dec|lea|xor|inc|mov|dec|add|inc|cmp|jbe|mov|inc|xor|dec|add|dec|lea|movsx|dec|inc|inc|ror|inc|add|cmp|jne|inc|lea|cmp|je|inc|inc|cmp|jb|jmp|inc|mov|add|dec|add|movzx|inc|mov|dec|add|mov|dec|add|jmp|xor|dec|mov|dec|mov|dec|add|pop|ret|int3|int3|int3|inc|mov|dec|mov|mov|push|push|push|push|inc|push|inc|push|inc|push|inc|push|dec|sub|dec|mov|inc|mov|mov|inc|mov|call|mov|dec|mov|call|mov|dec|mov|call|mov|dec|mov|call|dec|arpl|xor|dec|add|dec|mov|inc|mov|dec|mov|inc|lea|mov|call|inc|mov|dec|mov|dec|mov|inc|mov|dec|test|je|dec|mov|dec|sub|mov|mov|dec|add|dec|sub|jne|inc|movzx|movzx|dec|test|je|dec|lea|dec|add|mov|dec|sub|inc|mov|dec|add|inc|mov|dec|add|dec|test|je|inc|mov|dec|add|mov|dec|add|dec|sub|jne|dec|add|dec|test|jne|mov|dec|add|mov|test|je|dec|mov|mov|dec|add|inc|call|inc|mov|dec|mov|inc|mov|dec|add|dec|add|jmp|dec|cmp|jge|dec|arpl|inc|movzx|inc|mov|inc|mov|inc|mov|dec|sub|dec|add|mov|dec|add|jmp|dec|mov|dec|mov|dec|add|dec|add|call|dec|mov|dec|add|dec|add|dec|cmp|jne|mov|dec|add|test|jne|inc|mov|dec|mov|inc|mov|dec|mov|inc|mov|dec|sub|cmp|inc|lea|je|inc|mov|dec|add|inc|mov|test|je|mov|inc|mov|dec|lea|inc|mov|dec|add|dec|sub|dec|shr|je|inc|movzx|dec|sub|movzx|shr|cmp|jne|dec|and|dec|add|jmp|cmp|jne|dec|and|inc|add|jmp|cmp|jne|dec|and|dec|mov|dec|shr|add|jmp|inc|cmp|jne|dec|and|inc|add|dec|add|dec|test|jne|inc|mov|dec|add|inc|mov|test|jne|mov|inc|xor|xor|dec|or|dec|add|inc|call|dec|mov|mov|dec|mov|call|inc|test|je|cmp|je|mov|dec|add|inc|mov|inc|test|je|cmp|je|inc|mov|xor|inc|mov|dec|add|dec|add|inc|test|je|inc|mov|dec|add|xor|inc|movsx|dec|add|ror|add|inc|cmp|jne|inc|cmp|je|add|dec|add|dec|add|inc|cmp|jb|jmp|inc|movzx|cmp|je|mov|dec|mov|shl|dec|cwde|dec|add|inc|mov|inc|mov|dec|add|inc|call|dec|mov|dec|add|inc|pop|inc|pop|inc|pop|inc|pop|pop|pop|pop|pop|ret|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|push|dec|mov|dec|and|dec|sub|call|dec|mov|pop|ret
	----------^ SET rule0 ^-----------

		ShellCode/cobaltstrike.bin                                                                           0x10000000 - 0x10000435 in nonpefile

	[-] Remaining matches

	----------v SET rule0 v----------
	----------^ SET rule0 ^-----------

[+] Generating YARA rule for matches off of bytes from gold - ShellCode/cobaltstrike.bin

[+] Check 01 - Checking for exact byte match
	[*] Exact byte match found across all samples

[+] Completed YARA rules

/*

SAMPLES:

ShellCode/cobaltstrike.bin

BYTES:

E91B040000CCCCCC48895C24084889742410574883EC1065488B0425600000008BF1488B50184C8B4A104D8B41304D85C00F84B4000000410F1041584963403C33D24D8B09F30F7F0424428B9C008800000085DB74D4488B042448C1E810440FB7D04585D27421488B4C2408458BDA0FBE01C1CA0D8039617C0383C2E003D048FFC14983EB0175E74D8D141833C9418B7A204903F841394A18768F8B1F4533DB4903D8488D7F040FBE0348FFC341C1CB0D4403D8807BFF0075ED418D04133BC6740DFFC1413B4A1872D1E95BFFFFFF418B422403C94903C00FB71401418B4A1C4903C88B04914903C0EB0233C0488B5C2420488B7424284883C4105FC3CCCCCC44894C24204C89442418895424105355565741544155415641574883EC38488BE9458BE1B94C772607448BF2E8D7FEFFFFB949F702784C8BE8E8CAFEFFFFB958A453E54889842480000000E8B8FEFFFFB9AFB15C94488BD8E8ABFEFFFF4863753C33C94803F5488944242041B8003000004C8BF8448D49408B5650FFD3448B4654488BF8488BCD41BB010000004D85C07413488BD0482BD58A0188040A4903CB4D2BC375F3440FB74E060FB746144D85C97438488D4E2C4803C88B51F84D2BCB448B014803D7448B51FC4C03C54D85D27410418A004D03C388024903D34D2BD375F04883C1284D85C975CF8B9E900000004803DF8B430C85C00F8491000000488BAC24800000008BC84803CF41FFD5448B3B4C8BE0448B73104C03FF4C03F7EB4949833F007D29496344243C410FB717428B8C2088000000428B442110428B4C211C482BD04903CC8B04914903C4EB0F498B16498BCC4883C2024803D7FFD54989064983C6084983C70849833E0075B18B43204883C31485C0758C448BB424880000004C8B7C2420448BA424980000004C8BD741BD020000004C2B563083BEB400000000418D6DFF0F8497000000448B86B00000004C03C7418B400485C00F8481000000BBFF0F0000418B104D8D5808448BC84803D74983E90849D1E97457410FB70B4C2BCD0FB7C166C1E80C6683F80A75094823CB4C011411EB326683F80375094823CB44011411EB23663BC575104823CB498BC248C1E81066010411EB0E66413BC575084823CB66440114114D03DD4D85C975A9418B40044C03C0418B400485C075848B5E284533C033D24883C9FF4803DF41FFD74C8BC58BD5488BCFFFD34585F60F849300000083BE8C000000000F84860000008B96880000004803D7448B5A184585DB7474837A1400746E448B522033DB448B4A244C03D74C03CF4585DB7459458B024C03C733C9410FBE004C03C5C1C90D03C8418078FF0075ED443BF1741003DD4983C2044D03CD413BDB72D2EB29410FB70183F8FF74208B521C488B8C2490000000C1E00248984803C7448B0402418BD44C03C741FFD0488BC74883C438415F415E415D415C5F5E5D5BC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC56488BF44883E4F04883EC20E8CFFCFFFF488BE65EC3

INFO:

binsequencer.py -n -d -s ShellCode/cobaltstrike.bin
Match SUCCESS for morphing

*/

rule rule0
    {
        meta:
            description = "Autogenerated by Binsequencer v.1.0.4 from ShellCode/cobaltstrike.bin"
            author      = ""
            date        = "2017-11-28"

        strings:
            $rule0_bytes = { E91B040000CCCCCC48895C24084889742410574883EC1065488B0425600000008BF1488B50184C8B4A104D8B41304D85C00F84B4000000410F1041584963403C33D24D8B09F30F7F0424428B9C008800000085DB74D4488B042448C1E810440FB7D04585D27421488B4C2408458BDA0FBE01C1CA0D8039617C0383C2E003D048FFC14983EB0175E74D8D141833C9418B7A204903F841394A18768F8B1F4533DB4903D8488D7F040FBE0348FFC341C1CB0D4403D8807BFF0075ED418D04133BC6740DFFC1413B4A1872D1E95BFFFFFF418B422403C94903C00FB71401418B4A1C4903C88B04914903C0EB0233C0488B5C2420488B7424284883C4105FC3CCCCCC44894C24204C89442418895424105355565741544155415641574883EC38488BE9458BE1B94C772607448BF2E8D7FEFFFFB949F702784C8BE8E8CAFEFFFFB958A453E54889842480000000E8B8FEFFFFB9AFB15C94488BD8E8ABFEFFFF4863753C33C94803F5488944242041B8003000004C8BF8448D49408B5650FFD3448B4654488BF8488BCD41BB010000004D85C07413488BD0482BD58A0188040A4903CB4D2BC375F3440FB74E060FB746144D85C97438488D4E2C4803C88B51F84D2BCB448B014803D7448B51FC4C03C54D85D27410418A004D03C388024903D34D2BD375F04883C1284D85C975CF8B9E900000004803DF8B430C85C00F8491000000488BAC24800000008BC84803CF41FFD5448B3B4C8BE0448B73104C03FF4C03F7EB4949833F007D29496344243C410FB717428B8C2088000000428B442110428B4C211C482BD04903CC8B04914903C4EB0F498B16498BCC4883C2024803D7FFD54989064983C6084983C70849833E0075B18B43204883C31485C0758C448BB424880000004C8B7C2420448BA424980000004C8BD741BD020000004C2B563083BEB400000000418D6DFF0F8497000000448B86B00000004C03C7418B400485C00F8481000000BBFF0F0000418B104D8D5808448BC84803D74983E90849D1E97457410FB70B4C2BCD0FB7C166C1E80C6683F80A75094823CB4C011411EB326683F80375094823CB44011411EB23663BC575104823CB498BC248C1E81066010411EB0E66413BC575084823CB66440114114D03DD4D85C975A9418B40044C03C0418B400485C075848B5E284533C033D24883C9FF4803DF41FFD74C8BC58BD5488BCFFFD34585F60F849300000083BE8C000000000F84860000008B96880000004803D7448B5A184585DB7474837A1400746E448B522033DB448B4A244C03D74C03CF4585DB7459458B024C03C733C9410FBE004C03C5C1C90D03C8418078FF0075ED443BF1741003DD4983C2044D03CD413BDB72D2EB29410FB70183F8FF74208B521C488B8C2490000000C1E00248984803C7448B0402418BD44C03C741FFD0488BC74883C438415F415E415D415C5F5E5D5BC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC56488BF44883E4F04883EC20E8CFFCFFFF488BE65EC3 }

            $string_0 = { 41584963403C33 } // AXIc@<3
            $string_1 = { 5C242048 } // \$ H
            $string_2 = { 74242848 } // t$(H
            $string_3 = { 4C24204C } // L$ L
            $string_4 = { 53555657415441554156415748 } // SUVWATAUAVAWH
            $string_5 = { 4863753C33 } // Hcu<3
            $string_6 = { 44242041 } // D$ A
            $string_7 = { 7D29496344243C41 } // })IcD$<A
            $string_8 = { 7C242044 } // |$ D
            $string_9 = { 4C2B5630 } // L+V0
            $string_10 = { 5E284533 } // ^(E3
            $string_11 = { 38415F415E415D415C5F5E5D5B } // 8A_A^A]A\_^][

        condition:
            all of them
}
```

### [+] CHANGE LOG [+]

v1.0.7 - 09JUL2019
* Added some handling for YARA compilation issues - should remove bits of the rule till match occurs again

v1.0.4 - 30NOV2017
* Added ability to run on non-PE files.
* Added ability to run on single, individual files. Included option to force opcode technique since single files would always byte match.
* Cleaned up code significantly.
* Added "string" matching as well.
* Removed list as input so you specify a directory or file now.
* Modified how some of dynamic morphing works to be more precise - added INC, DEC, POP, and JMP as additional variants.

v1.0.3 - 04OCT2017
* Added two new methods for the byte matching - exact byte and same-length bytes.

v1.0.2 - 10JUN2016
* Full null-byte matches will now automatically be blacklisted.
* Minimum match will not exit now if there are kept matches.

v1.0.1 - 31MAY2016
* Added support for x64 code architecture. It will still work with x86 but the assembly won't be accurate. *-a*
* Added ability to accept default values for prompts. *-d*
* Added ability to override gold hash selection. *-g*
* Fleshed out multi-section support and logic.
* Added logic to hunt multiple matches across sections.
* Modified the way it identifies sections for analysis (uses header information along with execute permission bit).

v1.0.0 - 20MAY2016
* Initial release.
