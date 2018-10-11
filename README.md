# binsequencer
BinSequencer is a script designed to find a common pattern of bytes within a set of samples and generate a YARA rule from the identified pattern.

Blog post - [06JUN2018 - BinSequencer: Sequencing files for YARA Hunting](http://ropgadget.com/posts/intro_binsequencer.html)

Example output for 50 samples of Hancitor payloads:

```
$ python binsequencer.py Hancitor_Malware/

[+] Extracting instructions and generating sets

	[-]Hancitor_Malware/e7b3ef04c211fafa36772da62ab1d250970d27745182d0f3736896cf7673dc3a_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/6e73879ca49b40974cce575626e31541b49c07daa12ec2e9765c432bfac07a20_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/2b3c920dca2fd71ecadd0ae500b2be354d138841de649c89bacb9dee81e89fd4_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/87a10cc169f9ffd0c75bb9846a99fb477fc4329840964b02349ae44a672729c2_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/4843f33783788f273d8e56d4c2fb253527e3a1c1084bb8f5fc6ad35f29aac967_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/0858582ca7d96c7d588cd83f2ef4cb94fcef2e6f70fdb0d022dbceb63a1c9ccc_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/a26ecd4859456cd36d7cf3b12e92e318a7922e88ccb1558753c796f2cb08408d_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/f9efadc1f2ff65179f005704fafaf63b7d8f6d9bb6be3e08329126634df2d333_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/0cb34a9c52755ec21ad7eda70aecb961b9751441df65f93a928bf48819c2f7ae_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/ae079ad161c473a383174b2badcc874da7c188f1df48deb8b9ac407b5238cb47_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/de800b6bb8268a59d281cd3a859837c75be4fff3af634dfc64b041753d60c00f_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/e9f8b7b9faa8a61257c42ecec480c1a0b8855e7514122c7060c89f4ced2d592b_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/18046a720cd23c57981fdfed59e3df775476b0f189b7f52e2fe5f50e1e6003e7_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/846fe7d28d9134a06a3de32d7a102e481824cca8155549c889fb6809aedcbc2c_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/f4f026fbe3df5ee8ed848bd844fffb72b63006cfa8d1f053a9f3ee4c271e9188_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/0b400fa86c592d6c4fa1bca00ffb4740fe38e7ae5595c344d7bb17299291de7a_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/1c7f4150670158ab16e475f3641739d5adc40e191a64167f14c8c152be7fda82_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/f0420708c417376a52121f0a83c25a8b2051fffa5b3365205c34ac56e3d0065d_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/a984f3241483a2ba8c5eb0e269b397fadbbd2e444140af57599aa9772f738ae2_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/fff786ec23e6385e1d4f06dcf6859cc2ce0a32cee46d8f2a0c8fd780b3ecf89a_S1.exe
		.text - 3259 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/fed9cc2c7cfb97741470cb79c189a203545af88bdd67bc99e2d7499d343de653_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/0fac83312aaca0ae14fffd0bd125f48d2b72a51638e0b5e5ee24a98ede7312c9_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/fba0c13176f30040d6c78bb426ddaa5dd01afc45abb9b0ada8807f408167ca97_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/efe7cfe0c08265e1a4eed68a1e544ba0e98fff98942e0e55941e1899aba71579_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/40a8bb6e3eed57ed7bc802cc29b4e57360aa10c2de01d755f9577f07e10b848b_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/1c72f575d0c9574afcfcaab7e0b89fe0083dbe8ac20c0132a978eb1f6be59641_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/ab90ed6cb461f17ce1f901097a045aba7c984898a0425767f01454689698f2e9_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/594ab467454aafa64fc6bbf2b4aa92f7628d5861560eee1155805bd0987dbac3_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted
	[-]Hancitor_Malware/643951eee2dac8c3677f5ef7e9cb07444f12d165f6e401c1cd7afa27d7552367_S1.exe
		.text - 3740 instructions extracted
		.edata - 477 instructions extracted

[+] Golden hash (3736 instructions) - Hancitor_Malware/fff786ec23e6385e1d4f06dcf6859cc2ce0a32cee46d8f2a0c8fd780b3ecf89a_S1.exe

[+] Zeroing in longest mnemonic instruction set in .text

	[-] Matches - 0     Block Size - 3259  Time - 0.00 seconds
	[-] Matches - 0     Block Size - 1630  Time - 0.12 seconds
	[-] Matches - 0     Block Size - 816   Time - 0.13 seconds
	[-] Matches - 0     Block Size - 409   Time - 0.13 seconds
	[-] Matches - 0     Block Size - 206   Time - 0.12 seconds
	[-] Matches - 0     Block Size - 105   Time - 0.10 seconds
	[-] Matches - 0     Block Size - 55    Time - 0.08 seconds
	[-] Matches - 0     Block Size - 30    Time - 0.07 seconds

[+] Zeroing in longest mnemonic instruction set in .edata

	[-] Moving 1 instruction sets to review with a length of 477

    [*] Do you want to display matched instruction set? [Y/N] y

	push|mov|sub|push|push|push|call|mov|add|test|je|push|mov|lea|add|push|push|push|call|cmp|jne|test|je|mov|xor|test|je|xor|inc|cmp|jb|pop|mov|pop|mov|pop|ret|pop|xor|pop|mov|pop|ret|mov|pop|mov|pop|ret|int3|int3|int3|int3|int3|int3|int3|push|mov|push|push|call|dec|add|neg|sbb|inc|pop|ret|int3|int3|int3|int3|int3|push|mov|sub|mov|push|push|push|mov|xor|add|movzx|lea|movzx|add|mov|mov|test|je|mov|mov|mov|mov|movzx|or|sub|mov|mov|mov|mov|movzx|or|sub|jne|mov|test|je|mov|inc|movzx|or|movzx|or|sub|je|mov|mov|test|js|jg|je|inc|add|add|mov|cmp|jae|mov|jmp|mov|lea|pop|pop|pop|lea|mov|pop|ret|pop|pop|xor|pop|mov|pop|ret|int3|int3|int3|int3|int3|int3|int3|int3|int3|push|mov|mov|mov|and|sub|xor|sub|cmp|jne|cmp|je|inc|cmp|jl|xor|pop|ret|int3|int3|int3|int3|push|mov|sub|push|mov|xor|push|push|xor|mov|mov|add|mov|mov|add|mov|add|mov|add|mov|mov|mov|mov|mov|mov|test|je|movsx|mov|cmp|jae|cmp|jae|mov|mov|mov|mov|movzx|add|mov|or|movzx|or|sub|jne|sub|test|je|mov|inc|movzx|or|movzx|or|sub|je|test|js|jg|je|mov|inc|cmp|jae|mov|mov|jmp|mov|mov|mov|add|pop|pop|mov|pop|mov|pop|ret|pop|xor|pop|mov|pop|mov|pop|ret|pop|pop|xor|pop|mov|pop|ret|int3|int3|int3|push|xor|mov|js|mov|mov|lodsd|mov|jmp|mov|lea|mov|pop|ret|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|push|mov|sub|mov|push|push|push|mov|add|call|mov|push|push|call|mov|push|push|mov|call|push|push|mov|call|mov|add|mov|test|jne|test|je|test|je|mov|mov|add|mov|cmp|je|mov|mov|add|add|cmp|je|mov|mov|add|add|mov|test|je|push|call|jmp|test|je|push|push|push|call|mov|test|je|mov|test|movzx|js|lea|push|push|call|cmp|je|mov|mov|add|mov|add|mov|cmp|jne|mov|add|mov|cmp|jne|pop|pop|pop|mov|pop|ret|int3|int3|int3|int3|int3|int3|int3|int3|int3|push|push|call|mov|push|call|push|call|add|pop|test|jne|ret|call|int3|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add

    [*] Do you want to disassemble the underlying bytes? [Y/N] y

	0x10003000:	push       ebp                                      | 55
	0x10003001:	mov        ebp, esp                                 | 8BEC
	0x10003003:	sub        esp, 0x1c                                | 83EC1C
	0x10003006:	push       edi                                      | 57
	0x10003007:	push       dword ptr [ebp + 0xc]                    | FF750C
	0x1000300a:	push       dword ptr [ebp + 8]                      | FF7508
	0x1000300d:	call       0x10003090                               | E87E000000
	0x10003012:	mov        edi, eax                                 | 8BF8
	0x10003014:	add        esp, 8                                   | 83C408
	0x10003017:	test       edi, edi                                 | 85FF
	0x10003019:	je         0x1000305f                               | 7444
	0x1000301b:	push       esi                                      | 56
	0x1000301c:	mov        esi, dword ptr [edi + 0xc]               | 8B770C
	0x1000301f:	lea        eax, dword ptr [ebp - 0x1c]              | 8D45E4
	0x10003022:	add        esi, dword ptr [ebp + 8]                 | 037508
	0x10003025:	push       0x1c                                     | 6A1C
	0x10003027:	push       eax                                      | 50
	0x10003028:	push       esi                                      | 56
	0x10003029:	call       dword ptr [0x404064]                     | FF1564404000
	0x1000302f:	cmp        eax, 0x1c                                | 83F81C
	0x10003032:	jne        0x10003057                               | 7523
	0x10003034:	test       byte ptr [ebp - 8], 0x44                 | F645F844
	0x10003038:	je         0x10003057                               | 741D
	0x1000303a:	mov        ecx, dword ptr [edi + 0x10]              | 8B4F10
	0x1000303d:	xor        eax, eax                                 | 33C0
	0x1000303f:	test       ecx, ecx                                 | 85C9
	0x10003041:	je         0x1000304c                               | 7409
	0x10003043:	xor        byte ptr [eax + esi], 0xa1               | 803430A1
	0x10003047:	inc        eax                                      | 40
	0x10003048:	cmp        eax, ecx                                 | 3BC1
	0x1000304a:	jb         0x10003043                               | 72F7
	0x1000304c:	pop        esi                                      | 5E
	0x1000304d:	mov        eax, 1                                   | B801000000
	0x10003052:	pop        edi                                      | 5F
	0x10003053:	mov        esp, ebp                                 | 8BE5
	0x10003055:	pop        ebp                                      | 5D
	0x10003056:	ret                                                 | C3
	0x10003057:	pop        esi                                      | 5E
	0x10003058:	xor        eax, eax                                 | 33C0
	0x1000305a:	pop        edi                                      | 5F
	0x1000305b:	mov        esp, ebp                                 | 8BE5
	0x1000305d:	pop        ebp                                      | 5D
	0x1000305e:	ret                                                 | C3
	0x1000305f:	mov        eax, 1                                   | B801000000
	0x10003064:	pop        edi                                      | 5F
	0x10003065:	mov        esp, ebp                                 | 8BE5
	0x10003067:	pop        ebp                                      | 5D
	0x10003068:	ret                                                 | C3
	0x10003069:	int3                                                | CC
	0x1000306a:	int3                                                | CC
	0x1000306b:	int3                                                | CC
	0x1000306c:	int3                                                | CC
	0x1000306d:	int3                                                | CC
	0x1000306e:	int3                                                | CC
	0x1000306f:	int3                                                | CC
	0x10003070:	push       ebp                                      | 55
	0x10003071:	mov        ebp, esp                                 | 8BEC
	0x10003073:	push       0x4042bc                                 | 68BC424000
	0x10003078:	push       dword ptr [ebp + 8]                      | FF7508
	0x1000307b:	call       0x10003000                               | E880FFFFFF
	0x10003080:	dec        eax                                      | 48
	0x10003081:	add        esp, 8                                   | 83C408
	0x10003084:	neg        eax                                      | F7D8
	0x10003086:	sbb        eax, eax                                 | 1BC0
	0x10003088:	inc        eax                                      | 40
	0x10003089:	pop        ebp                                      | 5D
	0x1000308a:	ret                                                 | C3
	0x1000308b:	int3                                                | CC
	0x1000308c:	int3                                                | CC
	0x1000308d:	int3                                                | CC
	0x1000308e:	int3                                                | CC
	0x1000308f:	int3                                                | CC
	0x10003090:	push       ebp                                      | 55
	0x10003091:	mov        ebp, esp                                 | 8BEC
	0x10003093:	sub        esp, 0x10                                | 83EC10
	0x10003096:	mov        eax, dword ptr [ebp + 8]                 | 8B4508
	0x10003099:	push       ebx                                      | 53
	0x1000309a:	push       esi                                      | 56
	0x1000309b:	push       edi                                      | 57
	0x1000309c:	mov        ecx, dword ptr [eax + 0x3c]              | 8B483C
	0x1000309f:	xor        edi, edi                                 | 33FF
	0x100030a1:	add        ecx, eax                                 | 03C8
	0x100030a3:	movzx      eax, word ptr [ecx + 0x14]               | 0FB74114
	0x100030a7:	lea        edx, dword ptr [ecx + 0x18]              | 8D5118
	0x100030aa:	movzx      ebx, word ptr [ecx + 6]                  | 0FB75906
	0x100030ae:	add        edx, eax                                 | 03D0
	0x100030b0:	mov        dword ptr [ebp - 0x10], edx              | 8955F0
	0x100030b3:	mov        dword ptr [ebp - 0xc], ebx               | 895DF4
	0x100030b6:	test       ebx, ebx                                 | 85DB
	0x100030b8:	je         0x1000312e                               | 7474
	0x100030ba:	mov        eax, dword ptr [ebp + 0xc]               | 8B450C
	0x100030bd:	mov        esi, edx                                 | 8BF2
	0x100030bf:	mov        cl, byte ptr [eax]                       | 8A08
	0x100030c1:	mov        byte ptr [ebp + 0xb], cl                 | 884D0B
	0x100030c4:	movzx      ecx, cl                                  | 0FB6C9
	0x100030c7:	or         ecx, 0x20                                | 83C920
	0x100030ca:	sub        esi, eax                                 | 2BF0
	0x100030cc:	mov        dword ptr [ebp - 8], ecx                 | 894DF8
	0x100030cf:	mov        ecx, edx                                 | 8BCA
	0x100030d1:	mov        dword ptr [ebp - 4], ecx                 | 894DFC
	0x100030d4:	mov        edx, eax                                 | 8BD0
	0x100030d6:	movzx      eax, byte ptr [ecx]                      | 0FB601
	0x100030d9:	or         eax, 0x20                                | 83C820
	0x100030dc:	sub        eax, dword ptr [ebp - 8]                 | 2B45F8
	0x100030df:	jne        0x10003103                               | 7522
	0x100030e1:	mov        bl, byte ptr [ebp + 0xb]                 | 8A5D0B
	0x100030e4:	test       bl, bl                                   | 84DB
	0x100030e6:	je         0x100030fd                               | 7415
	0x100030e8:	mov        bl, byte ptr [edx + 1]                   | 8A5A01
	0x100030eb:	inc        edx                                      | 42
	0x100030ec:	movzx      ecx, bl                                  | 0FB6CB
	0x100030ef:	or         ecx, 0x20                                | 83C920
	0x100030f2:	movzx      eax, byte ptr [esi + edx]                | 0FB60416
	0x100030f6:	or         eax, 0x20                                | 83C820
	0x100030f9:	sub        eax, ecx                                 | 2BC1
	0x100030fb:	je         0x100030e4                               | 74E7
	0x100030fd:	mov        ecx, dword ptr [ebp - 4]                 | 8B4DFC
	0x10003100:	mov        ebx, dword ptr [ebp - 0xc]               | 8B5DF4
	0x10003103:	test       eax, eax                                 | 85C0
	0x10003105:	js         0x1000310b                               | 7804
	0x10003107:	jg         0x1000310b                               | 7F02
	0x10003109:	je         0x1000311e                               | 7413
	0x1000310b:	inc        edi                                      | 47
	0x1000310c:	add        ecx, 0x28                                | 83C128
	0x1000310f:	add        esi, 0x28                                | 83C628
	0x10003112:	mov        dword ptr [ebp - 4], ecx                 | 894DFC
	0x10003115:	cmp        edi, ebx                                 | 3BFB
	0x10003117:	jae        0x1000312e                               | 7315
	0x10003119:	mov        eax, dword ptr [ebp + 0xc]               | 8B450C
	0x1000311c:	jmp        0x100030d4                               | EBB6
	0x1000311e:	mov        ecx, dword ptr [ebp - 0x10]              | 8B4DF0
	0x10003121:	lea        eax, dword ptr [edi + edi*4]             | 8D04BF
	0x10003124:	pop        edi                                      | 5F
	0x10003125:	pop        esi                                      | 5E
	0x10003126:	pop        ebx                                      | 5B
	0x10003127:	lea        eax, dword ptr [ecx + eax*8]             | 8D04C1
	0x1000312a:	mov        esp, ebp                                 | 8BE5
	0x1000312c:	pop        ebp                                      | 5D
	0x1000312d:	ret                                                 | C3
	0x1000312e:	pop        edi                                      | 5F
	0x1000312f:	pop        esi                                      | 5E
	0x10003130:	xor        eax, eax                                 | 33C0
	0x10003132:	pop        ebx                                      | 5B
	0x10003133:	mov        esp, ebp                                 | 8BE5
	0x10003135:	pop        ebp                                      | 5D
	0x10003136:	ret                                                 | C3
	0x10003137:	int3                                                | CC
	0x10003138:	int3                                                | CC
	0x10003139:	int3                                                | CC
	0x1000313a:	int3                                                | CC
	0x1000313b:	int3                                                | CC
	0x1000313c:	int3                                                | CC
	0x1000313d:	int3                                                | CC
	0x1000313e:	int3                                                | CC
	0x1000313f:	int3                                                | CC
	0x10003140:	push       ebp                                      | 55
	0x10003141:	mov        ebp, esp                                 | 8BEC
	0x10003143:	mov        eax, dword ptr [ebp + 8]                 | 8B4508
	0x10003146:	mov        ecx, eax                                 | 8BC8
	0x10003148:	and        ecx, 0xfff                               | 81E1FF0F0000
	0x1000314e:	sub        eax, ecx                                 | 2BC1
	0x10003150:	xor        ecx, ecx                                 | 33C9
	0x10003152:	sub        eax, 0x1000                              | 2D00100000
	0x10003157:	cmp        byte ptr [eax], 0x4d                     | 80384D
	0x1000315a:	jne        0x10003162                               | 7506
	0x1000315c:	cmp        byte ptr [eax + 1], 0x5a                 | 8078015A
	0x10003160:	je         0x1000316a                               | 7408
	0x10003162:	inc        ecx                                      | 41
	0x10003163:	cmp        ecx, 0x64                                | 83F964
	0x10003166:	jl         0x10003152                               | 7CEA
	0x10003168:	xor        eax, eax                                 | 33C0
	0x1000316a:	pop        ebp                                      | 5D
	0x1000316b:	ret                                                 | C3
	0x1000316c:	int3                                                | CC
	0x1000316d:	int3                                                | CC
	0x1000316e:	int3                                                | CC
	0x1000316f:	int3                                                | CC
	0x10003170:	push       ebp                                      | 55
	0x10003171:	mov        ebp, esp                                 | 8BEC
	0x10003173:	sub        esp, 0x18                                | 83EC18
	0x10003176:	push       ebx                                      | 53
	0x10003177:	mov        ebx, dword ptr [ebp + 8]                 | 8B5D08
	0x1000317a:	xor        edx, edx                                 | 33D2
	0x1000317c:	push       esi                                      | 56
	0x1000317d:	push       edi                                      | 57
	0x1000317e:	xor        esi, esi                                 | 33F6
	0x10003180:	mov        eax, dword ptr [ebx + 0x3c]              | 8B433C
	0x10003183:	mov        eax, dword ptr [eax + ebx + 0x78]        | 8B441878
	0x10003187:	add        eax, ebx                                 | 03C3
	0x10003189:	mov        ecx, dword ptr [eax + 0x1c]              | 8B481C
	0x1000318c:	mov        edi, dword ptr [eax + 0x24]              | 8B7824
	0x1000318f:	add        ecx, ebx                                 | 03CB
	0x10003191:	mov        dword ptr [ebp - 0x18], ecx              | 894DE8
	0x10003194:	add        edi, ebx                                 | 03FB
	0x10003196:	mov        ecx, dword ptr [eax + 0x20]              | 8B4820
	0x10003199:	add        ecx, ebx                                 | 03CB
	0x1000319b:	mov        dword ptr [ebp - 0x10], edi              | 897DF0
	0x1000319e:	mov        dword ptr [ebp - 8], ecx                 | 894DF8
	0x100031a1:	mov        ecx, dword ptr [eax + 0x18]              | 8B4818
	0x100031a4:	mov        eax, dword ptr [eax + 0x14]              | 8B4014
	0x100031a7:	mov        dword ptr [ebp - 0xc], ecx               | 894DF4
	0x100031aa:	mov        dword ptr [ebp - 4], eax                 | 8945FC
	0x100031ad:	test       ecx, ecx                                 | 85C9
	0x100031af:	je         0x10003220                               | 746F
	0x100031b1:	movsx      eax, word ptr [edi + esi*2]              | 0FBF0477
	0x100031b5:	mov        dword ptr [ebp - 0x14], eax              | 8945EC
	0x100031b8:	cmp        esi, ecx                                 | 3BF1
	0x100031ba:	jae        0x10003234                               | 7378
	0x100031bc:	cmp        eax, dword ptr [ebp - 4]                 | 3B45FC
	0x100031bf:	jae        0x10003234                               | 7373
	0x100031c1:	mov        eax, dword ptr [ebp - 8]                 | 8B45F8
	0x100031c4:	mov        ecx, dword ptr [ebp + 0xc]               | 8B4D0C
	0x100031c7:	mov        edx, ecx                                 | 8BD1
	0x100031c9:	mov        edi, dword ptr [eax + esi*4]             | 8B3CB0
	0x100031cc:	movzx      eax, byte ptr [edi + ebx]                | 0FB6041F
	0x100031d0:	add        edi, ebx                                 | 03FB
	0x100031d2:	mov        bl, byte ptr [ecx]                       | 8A19
	0x100031d4:	or         eax, 0x20                                | 83C820
	0x100031d7:	movzx      ecx, bl                                  | 0FB6CB
	0x100031da:	or         ecx, 0x20                                | 83C920
	0x100031dd:	sub        eax, ecx                                 | 2BC1
	0x100031df:	jne        0x100031fc                               | 751B
	0x100031e1:	sub        edi, edx                                 | 2BFA
	0x100031e3:	test       bl, bl                                   | 84DB
	0x100031e5:	je         0x100031fc                               | 7415
	0x100031e7:	mov        bl, byte ptr [edx + 1]                   | 8A5A01
	0x100031ea:	inc        edx                                      | 42
	0x100031eb:	movzx      ecx, bl                                  | 0FB6CB
	0x100031ee:	or         ecx, 0x20                                | 83C920
	0x100031f1:	movzx      eax, byte ptr [edi + edx]                | 0FB60417
	0x100031f5:	or         eax, 0x20                                | 83C820
	0x100031f8:	sub        eax, ecx                                 | 2BC1
	0x100031fa:	je         0x100031e3                               | 74E7
	0x100031fc:	test       eax, eax                                 | 85C0
	0x100031fe:	js         0x10003204                               | 7804
	0x10003200:	jg         0x10003204                               | 7F02
	0x10003202:	je         0x10003214                               | 7410
	0x10003204:	mov        ecx, dword ptr [ebp - 0xc]               | 8B4DF4
	0x10003207:	inc        esi                                      | 46
	0x10003208:	cmp        esi, ecx                                 | 3BF1
	0x1000320a:	jae        0x10003229                               | 731D
	0x1000320c:	mov        ebx, dword ptr [ebp + 8]                 | 8B5D08
	0x1000320f:	mov        edi, dword ptr [ebp - 0x10]              | 8B7DF0
	0x10003212:	jmp        0x100031b1                               | EB9D
	0x10003214:	mov        eax, dword ptr [ebp - 0x14]              | 8B45EC
	0x10003217:	mov        edx, dword ptr [ebp - 0x18]              | 8B55E8
	0x1000321a:	mov        edx, dword ptr [edx + eax*4]             | 8B1482
	0x1000321d:	add        edx, dword ptr [ebp + 8]                 | 035508
	0x10003220:	pop        edi                                      | 5F
	0x10003221:	pop        esi                                      | 5E
	0x10003222:	mov        eax, edx                                 | 8BC2
	0x10003224:	pop        ebx                                      | 5B
	0x10003225:	mov        esp, ebp                                 | 8BE5
	0x10003227:	pop        ebp                                      | 5D
	0x10003228:	ret                                                 | C3
	0x10003229:	pop        edi                                      | 5F
	0x1000322a:	xor        edx, edx                                 | 33D2
	0x1000322c:	pop        esi                                      | 5E
	0x1000322d:	mov        eax, edx                                 | 8BC2
	0x1000322f:	pop        ebx                                      | 5B
	0x10003230:	mov        esp, ebp                                 | 8BE5
	0x10003232:	pop        ebp                                      | 5D
	0x10003233:	ret                                                 | C3
	0x10003234:	pop        edi                                      | 5F
	0x10003235:	pop        esi                                      | 5E
	0x10003236:	xor        eax, eax                                 | 33C0
	0x10003238:	pop        ebx                                      | 5B
	0x10003239:	mov        esp, ebp                                 | 8BE5
	0x1000323b:	pop        ebp                                      | 5D
	0x1000323c:	ret                                                 | C3
	0x1000323d:	int3                                                | CC
	0x1000323e:	int3                                                | CC
	0x1000323f:	int3                                                | CC
	0x10003240:	push       esi                                      | 56
	0x10003241:	xor        eax, eax                                 | 33C0
	0x10003243:	mov        eax, dword ptr fs:[0x30]                 | 64A130000000
	0x10003249:	js         0x10003257                               | 780C
	0x1000324b:	mov        eax, dword ptr [eax + 0xc]               | 8B400C
	0x1000324e:	mov        esi, dword ptr [eax + 0x1c]              | 8B701C
	0x10003251:	lodsd      eax, dword ptr [esi]                     | AD
	0x10003252:	mov        eax, dword ptr [eax + 8]                 | 8B4008
	0x10003255:	jmp        0x10003260                               | EB09
	0x10003257:	mov        eax, dword ptr [eax + 0x34]              | 8B4034
	0x1000325a:	lea        eax, dword ptr [eax + 0x7c]              | 8D407C
	0x1000325d:	mov        eax, dword ptr [eax + 0x3c]              | 8B403C
	0x10003260:	pop        esi                                      | 5E
	0x10003261:	ret                                                 | C3
	0x10003262:	int3                                                | CC
	0x10003263:	int3                                                | CC
	0x10003264:	int3                                                | CC
	0x10003265:	int3                                                | CC
	0x10003266:	int3                                                | CC
	0x10003267:	int3                                                | CC
	0x10003268:	int3                                                | CC
	0x10003269:	int3                                                | CC
	0x1000326a:	int3                                                | CC
	0x1000326b:	int3                                                | CC
	0x1000326c:	int3                                                | CC
	0x1000326d:	int3                                                | CC
	0x1000326e:	int3                                                | CC
	0x1000326f:	int3                                                | CC
	0x10003270:	push       ebp                                      | 55
	0x10003271:	mov        ebp, esp                                 | 8BEC
	0x10003273:	sub        esp, 0x10                                | 83EC10
	0x10003276:	mov        ecx, dword ptr [ebp + 8]                 | 8B4D08
	0x10003279:	push       ebx                                      | 53
	0x1000327a:	push       esi                                      | 56
	0x1000327b:	push       edi                                      | 57
	0x1000327c:	mov        edi, dword ptr [ecx + 0x3c]              | 8B793C
	0x1000327f:	add        edi, ecx                                 | 03F9
	0x10003281:	call       0x10003240                               | E8BAFFFFFF
	0x10003286:	mov        esi, eax                                 | 8BF0
	0x10003288:	push       0x40428c                                 | 688C424000
	0x1000328d:	push       esi                                      | 56
	0x1000328e:	call       0x10003170                               | E8DDFEFFFF
	0x10003293:	mov        ebx, eax                                 | 8BD8
	0x10003295:	push       0x40429c                                 | 689C424000
	0x1000329a:	push       esi                                      | 56
	0x1000329b:	mov        dword ptr [ebp - 0x10], ebx              | 895DF0
	0x1000329e:	call       0x10003170                               | E8CDFEFFFF
	0x100032a3:	push       0x4042ac                                 | 68AC424000
	0x100032a8:	push       esi                                      | 56
	0x100032a9:	mov        dword ptr [ebp - 4], eax                 | 8945FC
	0x100032ac:	call       0x10003170                               | E8BFFEFFFF
	0x100032b1:	mov        edx, dword ptr [ebp - 4]                 | 8B55FC
	0x100032b4:	add        esp, 0x18                                | 83C418
	0x100032b7:	mov        dword ptr [ebp - 8], eax                 | 8945F8
	0x100032ba:	test       ebx, ebx                                 | 85DB
	0x100032bc:	jne        0x100032c6                               | 7508
	0x100032be:	test       edx, edx                                 | 85D2
	0x100032c0:	je         0x10003350                               | 0F848A000000
	0x100032c6:	test       eax, eax                                 | 85C0
	0x100032c8:	je         0x10003350                               | 0F8482000000
	0x100032ce:	mov        eax, dword ptr [edi + 0x80]              | 8B8780000000
	0x100032d4:	mov        ecx, dword ptr [ebp + 8]                 | 8B4D08
	0x100032d7:	add        eax, ecx                                 | 03C1
	0x100032d9:	mov        dword ptr [ebp - 0xc], eax               | 8945F4
	0x100032dc:	cmp        dword ptr [eax + 0xc], 0                 | 83780C00
	0x100032e0:	je         0x10003350                               | 746E
	0x100032e2:	mov        esi, dword ptr [eax + 0x10]              | 8B7010
	0x100032e5:	mov        edi, dword ptr [eax]                     | 8B38
	0x100032e7:	add        esi, ecx                                 | 03F1
	0x100032e9:	add        edi, ecx                                 | 03F9
	0x100032eb:	cmp        dword ptr [esi], 0                       | 833E00
	0x100032ee:	je         0x10003341                               | 7451
	0x100032f0:	mov        ebx, dword ptr [edi]                     | 8B1F
	0x100032f2:	mov        eax, dword ptr [eax + 0xc]               | 8B400C
	0x100032f5:	add        ebx, ecx                                 | 03D9
	0x100032f7:	add        eax, ecx                                 | 03C1
	0x100032f9:	mov        ecx, dword ptr [ebp - 0x10]              | 8B4DF0
	0x100032fc:	test       ecx, ecx                                 | 85C9
	0x100032fe:	je         0x10003305                               | 7405
	0x10003300:	push       eax                                      | 50
	0x10003301:	call       ecx                                      | FFD1
	0x10003303:	jmp        0x10003310                               | EB0B
	0x10003305:	test       edx, edx                                 | 85D2
	0x10003307:	je         0x10003350                               | 7447
	0x10003309:	push       0                                        | 6A00
	0x1000330b:	push       0                                        | 6A00
	0x1000330d:	push       eax                                      | 50
	0x1000330e:	call       edx                                      | FFD2
	0x10003310:	mov        ecx, eax                                 | 8BC8
	0x10003312:	test       ecx, ecx                                 | 85C9
	0x10003314:	je         0x10003350                               | 743A
	0x10003316:	mov        eax, dword ptr [edi]                     | 8B07
	0x10003318:	test       eax, eax                                 | 85C0
	0x1000331a:	movzx      eax, ax                                  | 0FB7C0
	0x1000331d:	js         0x10003322                               | 7803
	0x1000331f:	lea        eax, dword ptr [ebx + 2]                 | 8D4302
	0x10003322:	push       eax                                      | 50
	0x10003323:	push       ecx                                      | 51
	0x10003324:	call       dword ptr [ebp - 8]                      | FF55F8
	0x10003327:	cmp        dword ptr [esi], eax                     | 3906
	0x10003329:	je         0x1000332d                               | 7402
	0x1000332b:	mov        dword ptr [esi], eax                     | 8906
	0x1000332d:	mov        eax, dword ptr [ebp - 0xc]               | 8B45F4
	0x10003330:	add        esi, 4                                   | 83C604
	0x10003333:	mov        ecx, dword ptr [ebp + 8]                 | 8B4D08
	0x10003336:	add        edi, 4                                   | 83C704
	0x10003339:	mov        edx, dword ptr [ebp - 4]                 | 8B55FC
	0x1000333c:	cmp        dword ptr [esi], 0                       | 833E00
	0x1000333f:	jne        0x100032f0                               | 75AF
	0x10003341:	mov        edx, dword ptr [ebp - 4]                 | 8B55FC
	0x10003344:	add        eax, 0x14                                | 83C014
	0x10003347:	mov        dword ptr [ebp - 0xc], eax               | 8945F4
	0x1000334a:	cmp        dword ptr [eax + 0xc], 0                 | 83780C00
	0x1000334e:	jne        0x100032e2                               | 7592
	0x10003350:	pop        edi                                      | 5F
	0x10003351:	pop        esi                                      | 5E
	0x10003352:	pop        ebx                                      | 5B
	0x10003353:	mov        esp, ebp                                 | 8BE5
	0x10003355:	pop        ebp                                      | 5D
	0x10003356:	ret                                                 | C3
	0x10003357:	int3                                                | CC
	0x10003358:	int3                                                | CC
	0x10003359:	int3                                                | CC
	0x1000335a:	int3                                                | CC
	0x1000335b:	int3                                                | CC
	0x1000335c:	int3                                                | CC
	0x1000335d:	int3                                                | CC
	0x1000335e:	int3                                                | CC
	0x1000335f:	int3                                                | CC
	0x10003360:	push       esi                                      | 56
	0x10003361:	push       0x403360                                 | 6860334000
	0x10003366:	call       0x10003140                               | E8D5FDFFFF
	0x1000336b:	mov        esi, eax                                 | 8BF0
	0x1000336d:	push       esi                                      | 56
	0x1000336e:	call       0x10003270                               | E8FDFEFFFF
	0x10003373:	push       esi                                      | 56
	0x10003374:	call       0x10003070                               | E8F7FCFFFF
	0x10003379:	add        esp, 0xc                                 | 83C40C
	0x1000337c:	pop        esi                                      | 5E
	0x1000337d:	test       eax, eax                                 | 85C0
	0x1000337f:	jne        0x10003382                               | 7501
	0x10003381:	ret                                                 | C3
	0x10003382:	call       0x10002010                               | E889ECFFFF
	0x10003387:	int3                                                | CC
	0x10003388:	add        byte ptr [eax], al                       | 0000
	0x1000338a:	add        byte ptr [eax], al                       | 0000
	0x1000338c:	add        byte ptr [eax], al                       | 0000
	0x1000338e:	add        byte ptr [eax], al                       | 0000
	0x10003390:	add        byte ptr [eax], al                       | 0000
	0x10003392:	add        byte ptr [eax], al                       | 0000
	0x10003394:	add        byte ptr [eax], al                       | 0000
	0x10003396:	add        byte ptr [eax], al                       | 0000
	0x10003398:	add        byte ptr [eax], al                       | 0000
	0x1000339a:	add        byte ptr [eax], al                       | 0000
	0x1000339c:	add        byte ptr [eax], al                       | 0000
	0x1000339e:	add        byte ptr [eax], al                       | 0000
	0x100033a0:	add        byte ptr [eax], al                       | 0000
	0x100033a2:	add        byte ptr [eax], al                       | 0000
	0x100033a4:	add        byte ptr [eax], al                       | 0000
	0x100033a6:	add        byte ptr [eax], al                       | 0000
	0x100033a8:	add        byte ptr [eax], al                       | 0000
	0x100033aa:	add        byte ptr [eax], al                       | 0000
	0x100033ac:	add        byte ptr [eax], al                       | 0000
	0x100033ae:	add        byte ptr [eax], al                       | 0000
	0x100033b0:	add        byte ptr [eax], al                       | 0000
	0x100033b2:	add        byte ptr [eax], al                       | 0000
	0x100033b4:	add        byte ptr [eax], al                       | 0000
	0x100033b6:	add        byte ptr [eax], al                       | 0000
	0x100033b8:	add        byte ptr [eax], al                       | 0000
	0x100033ba:	add        byte ptr [eax], al                       | 0000
	0x100033bc:	add        byte ptr [eax], al                       | 0000
	0x100033be:	add        byte ptr [eax], al                       | 0000
	0x100033c0:	add        byte ptr [eax], al                       | 0000
	0x100033c2:	add        byte ptr [eax], al                       | 0000
	0x100033c4:	add        byte ptr [eax], al                       | 0000
	0x100033c6:	add        byte ptr [eax], al                       | 0000
	0x100033c8:	add        byte ptr [eax], al                       | 0000
	0x100033ca:	add        byte ptr [eax], al                       | 0000
	0x100033cc:	add        byte ptr [eax], al                       | 0000
	0x100033ce:	add        byte ptr [eax], al                       | 0000
	0x100033d0:	add        byte ptr [eax], al                       | 0000
	0x100033d2:	add        byte ptr [eax], al                       | 0000
	0x100033d4:	add        byte ptr [eax], al                       | 0000
	0x100033d6:	add        byte ptr [eax], al                       | 0000
	0x100033d8:	add        byte ptr [eax], al                       | 0000
	0x100033da:	add        byte ptr [eax], al                       | 0000
	0x100033dc:	add        byte ptr [eax], al                       | 0000
	0x100033de:	add        byte ptr [eax], al                       | 0000
	0x100033e0:	add        byte ptr [eax], al                       | 0000
	0x100033e2:	add        byte ptr [eax], al                       | 0000
	0x100033e4:	add        byte ptr [eax], al                       | 0000
	0x100033e6:	add        byte ptr [eax], al                       | 0000
	0x100033e8:	add        byte ptr [eax], al                       | 0000
	0x100033ea:	add        byte ptr [eax], al                       | 0000
	0x100033ec:	add        byte ptr [eax], al                       | 0000
	0x100033ee:	add        byte ptr [eax], al                       | 0000
	0x100033f0:	add        byte ptr [eax], al                       | 0000
	0x100033f2:	add        byte ptr [eax], al                       | 0000
	0x100033f4:	add        byte ptr [eax], al                       | 0000
	0x100033f6:	add        byte ptr [eax], al                       | 0000
	0x100033f8:	add        byte ptr [eax], al                       | 0000
	0x100033fa:	add        byte ptr [eax], al                       | 0000
	0x100033fc:	add        byte ptr [eax], al                       | 0000
	0x100033fe:	add        byte ptr [eax], al                       | 0000

    [*] Do you want to display the raw byte blob? [Y/N] y

	558BEC83EC1C57FF750CFF7508E87E0000008BF883C40885FF7444568B770C8D45E40375086A1C5056FF156440400083F81C7523F645F844741D8B4F1033C085C97409803430A1403BC172F75EB8010000005F8BE55DC35E33C05F8BE55DC3B8010000005F8BE55DC3CCCCCCCCCCCCCC558BEC68BC424000FF7508E880FFFFFF4883C408F7D81BC0405DC3CCCCCCCCCC558BEC83EC108B45085356578B483C33FF03C80FB741148D51180FB7590603D08955F0895DF485DB74748B450C8BF28A08884D0B0FB6C983C9202BF0894DF88BCA894DFC8BD00FB60183C8202B45F875228A5D0B84DB74158A5A01420FB6CB83C9200FB6041683C8202BC174E78B4DFC8B5DF485C078047F0274134783C12883C628894DFC3BFB73158B450CEBB68B4DF08D04BF5F5E5B8D04C18BE55DC35F5E33C05B8BE55DC3CCCCCCCCCCCCCCCCCC558BEC8B45088BC881E1FF0F00002BC133C92D0010000080384D75068078015A74084183F9647CEA33C05DC3CCCCCCCC558BEC83EC18538B5D0833D2565733F68B433C8B44187803C38B481C8B782403CB894DE803FB8B482003CB897DF0894DF88B48188B4014894DF48945FC85C9746F0FBF04778945EC3BF173783B45FC73738B45F88B4D0C8BD18B3CB00FB6041F03FB8A1983C8200FB6CB83C9202BC1751B2BFA84DB74158A5A01420FB6CB83C9200FB6041783C8202BC174E785C078047F0274108B4DF4463BF1731D8B5D088B7DF0EB9D8B45EC8B55E88B14820355085F5E8BC25B8BE55DC35F33D25E8BC25B8BE55DC35F5E33C05B8BE55DC3CCCCCC5633C064A130000000780C8B400C8B701CAD8B4008EB098B40348D407C8B403C5EC3CCCCCCCCCCCCCCCCCCCCCCCCCCCC558BEC83EC108B4D085356578B793C03F9E8BAFFFFFF8BF0688C42400056E8DDFEFFFF8BD8689C42400056895DF0E8CDFEFFFF68AC424000568945FCE8BFFEFFFF8B55FC83C4188945F885DB750885D20F848A00000085C00F84820000008B87800000008B4D0803C18945F483780C00746E8B70108B3803F103F9833E0074518B1F8B400C03D903C18B4DF085C9740550FFD1EB0B85D274476A006A0050FFD28BC885C9743A8B0785C00FB7C078038D43025051FF55F83906740289068B45F483C6048B4D0883C7048B55FC833E0075AF8B55FC83C0148945F483780C0075925F5E5B8BE55DC3CCCCCCCCCCCCCCCCCC566860334000E8D5FDFFFF8BF056E8FDFEFFFF56E8F7FCFFFF83C40C5E85C07501C3E889ECFFFFCC000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

    [*] Do you want to keep this set? [Y/N] y

[+] Keeping 1 mnemonic set using 100 % commonality out of 29 hashes

	[-] Length - 477   Section - .edata

[+] Printing offsets of type: longest

	[-] Gold matches

	----------v SET rule0 v----------
	push|mov|sub|push|push|push|call|mov|add|test|je|push|mov|lea|add|push|push|push|call|cmp|jne|test|je|mov|xor|test|je|xor|inc|cmp|jb|pop|mov|pop|mov|pop|ret|pop|xor|pop|mov|pop|ret|mov|pop|mov|pop|ret|int3|int3|int3|int3|int3|int3|int3|push|mov|push|push|call|dec|add|neg|sbb|inc|pop|ret|int3|int3|int3|int3|int3|push|mov|sub|mov|push|push|push|mov|xor|add|movzx|lea|movzx|add|mov|mov|test|je|mov|mov|mov|mov|movzx|or|sub|mov|mov|mov|mov|movzx|or|sub|jne|mov|test|je|mov|inc|movzx|or|movzx|or|sub|je|mov|mov|test|js|jg|je|inc|add|add|mov|cmp|jae|mov|jmp|mov|lea|pop|pop|pop|lea|mov|pop|ret|pop|pop|xor|pop|mov|pop|ret|int3|int3|int3|int3|int3|int3|int3|int3|int3|push|mov|mov|mov|and|sub|xor|sub|cmp|jne|cmp|je|inc|cmp|jl|xor|pop|ret|int3|int3|int3|int3|push|mov|sub|push|mov|xor|push|push|xor|mov|mov|add|mov|mov|add|mov|add|mov|add|mov|mov|mov|mov|mov|mov|test|je|movsx|mov|cmp|jae|cmp|jae|mov|mov|mov|mov|movzx|add|mov|or|movzx|or|sub|jne|sub|test|je|mov|inc|movzx|or|movzx|or|sub|je|test|js|jg|je|mov|inc|cmp|jae|mov|mov|jmp|mov|mov|mov|add|pop|pop|mov|pop|mov|pop|ret|pop|xor|pop|mov|pop|mov|pop|ret|pop|pop|xor|pop|mov|pop|ret|int3|int3|int3|push|xor|mov|js|mov|mov|lodsd|mov|jmp|mov|lea|mov|pop|ret|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|int3|push|mov|sub|mov|push|push|push|mov|add|call|mov|push|push|call|mov|push|push|mov|call|push|push|mov|call|mov|add|mov|test|jne|test|je|test|je|mov|mov|add|mov|cmp|je|mov|mov|add|add|cmp|je|mov|mov|add|add|mov|test|je|push|call|jmp|test|je|push|push|push|call|mov|test|je|mov|test|movzx|js|lea|push|push|call|cmp|je|mov|mov|add|mov|add|mov|cmp|jne|mov|add|mov|cmp|jne|pop|pop|pop|mov|pop|ret|int3|int3|int3|int3|int3|int3|int3|int3|int3|push|push|call|mov|push|call|push|call|add|pop|test|jne|ret|call|int3|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add|add
	----------^ SET rule0 ^-----------

		Hancitor_Malware/fff786ec23e6385e1d4f06dcf6859cc2ce0a32cee46d8f2a0c8fd780b3ecf89a_S1.exe             0x10003000 - 0x100033fe in .edata

	[-] Remaining matches

	----------v SET rule0 v----------
		Hancitor_Malware/e7b3ef04c211fafa36772da62ab1d250970d27745182d0f3736896cf7673dc3a_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/6e73879ca49b40974cce575626e31541b49c07daa12ec2e9765c432bfac07a20_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/2b3c920dca2fd71ecadd0ae500b2be354d138841de649c89bacb9dee81e89fd4_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/87a10cc169f9ffd0c75bb9846a99fb477fc4329840964b02349ae44a672729c2_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/4843f33783788f273d8e56d4c2fb253527e3a1c1084bb8f5fc6ad35f29aac967_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/0858582ca7d96c7d588cd83f2ef4cb94fcef2e6f70fdb0d022dbceb63a1c9ccc_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/a26ecd4859456cd36d7cf3b12e92e318a7922e88ccb1558753c796f2cb08408d_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/f9efadc1f2ff65179f005704fafaf63b7d8f6d9bb6be3e08329126634df2d333_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/0cb34a9c52755ec21ad7eda70aecb961b9751441df65f93a928bf48819c2f7ae_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/ae079ad161c473a383174b2badcc874da7c188f1df48deb8b9ac407b5238cb47_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/de800b6bb8268a59d281cd3a859837c75be4fff3af634dfc64b041753d60c00f_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/e9f8b7b9faa8a61257c42ecec480c1a0b8855e7514122c7060c89f4ced2d592b_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/18046a720cd23c57981fdfed59e3df775476b0f189b7f52e2fe5f50e1e6003e7_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/846fe7d28d9134a06a3de32d7a102e481824cca8155549c889fb6809aedcbc2c_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/f4f026fbe3df5ee8ed848bd844fffb72b63006cfa8d1f053a9f3ee4c271e9188_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/0b400fa86c592d6c4fa1bca00ffb4740fe38e7ae5595c344d7bb17299291de7a_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/1c7f4150670158ab16e475f3641739d5adc40e191a64167f14c8c152be7fda82_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/f0420708c417376a52121f0a83c25a8b2051fffa5b3365205c34ac56e3d0065d_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/a984f3241483a2ba8c5eb0e269b397fadbbd2e444140af57599aa9772f738ae2_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/fed9cc2c7cfb97741470cb79c189a203545af88bdd67bc99e2d7499d343de653_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/0fac83312aaca0ae14fffd0bd125f48d2b72a51638e0b5e5ee24a98ede7312c9_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/fba0c13176f30040d6c78bb426ddaa5dd01afc45abb9b0ada8807f408167ca97_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/efe7cfe0c08265e1a4eed68a1e544ba0e98fff98942e0e55941e1899aba71579_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/40a8bb6e3eed57ed7bc802cc29b4e57360aa10c2de01d755f9577f07e10b848b_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/1c72f575d0c9574afcfcaab7e0b89fe0083dbe8ac20c0132a978eb1f6be59641_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/ab90ed6cb461f17ce1f901097a045aba7c984898a0425767f01454689698f2e9_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/594ab467454aafa64fc6bbf2b4aa92f7628d5861560eee1155805bd0987dbac3_S1.exe             0x10003000 - 0x100033fe in .edata
		Hancitor_Malware/643951eee2dac8c3677f5ef7e9cb07444f12d165f6e401c1cd7afa27d7552367_S1.exe             0x10003000 - 0x100033fe in .edata
	----------^ SET rule0 ^-----------

[+] Generating YARA rule for matches off of bytes from gold - Hancitor_Malware/fff786ec23e6385e1d4f06dcf6859cc2ce0a32cee46d8f2a0c8fd780b3ecf89a_S1.exe

    [*] Do you want to try and morph rule0 for accuracy and attempt to make it VT Retro friendly [Y/N] y

    [*] Do you want to include matched sample names in rule meta? [Y/N] y

    [*] Do you want to include matched byte sequence in rule comments? [Y/N] y

[+] Completed YARA rules

/*

SAMPLES:

Hancitor_Malware/18046a720cd23c57981fdfed59e3df775476b0f189b7f52e2fe5f50e1e6003e7_S1.exe
Hancitor_Malware/f4f026fbe3df5ee8ed848bd844fffb72b63006cfa8d1f053a9f3ee4c271e9188_S1.exe
Hancitor_Malware/0858582ca7d96c7d588cd83f2ef4cb94fcef2e6f70fdb0d022dbceb63a1c9ccc_S1.exe
Hancitor_Malware/e9f8b7b9faa8a61257c42ecec480c1a0b8855e7514122c7060c89f4ced2d592b_S1.exe
Hancitor_Malware/643951eee2dac8c3677f5ef7e9cb07444f12d165f6e401c1cd7afa27d7552367_S1.exe
Hancitor_Malware/0fac83312aaca0ae14fffd0bd125f48d2b72a51638e0b5e5ee24a98ede7312c9_S1.exe
Hancitor_Malware/6e73879ca49b40974cce575626e31541b49c07daa12ec2e9765c432bfac07a20_S1.exe
Hancitor_Malware/efe7cfe0c08265e1a4eed68a1e544ba0e98fff98942e0e55941e1899aba71579_S1.exe
Hancitor_Malware/fba0c13176f30040d6c78bb426ddaa5dd01afc45abb9b0ada8807f408167ca97_S1.exe
Hancitor_Malware/4843f33783788f273d8e56d4c2fb253527e3a1c1084bb8f5fc6ad35f29aac967_S1.exe
Hancitor_Malware/594ab467454aafa64fc6bbf2b4aa92f7628d5861560eee1155805bd0987dbac3_S1.exe
Hancitor_Malware/a984f3241483a2ba8c5eb0e269b397fadbbd2e444140af57599aa9772f738ae2_S1.exe
Hancitor_Malware/87a10cc169f9ffd0c75bb9846a99fb477fc4329840964b02349ae44a672729c2_S1.exe
Hancitor_Malware/0b400fa86c592d6c4fa1bca00ffb4740fe38e7ae5595c344d7bb17299291de7a_S1.exe
Hancitor_Malware/2b3c920dca2fd71ecadd0ae500b2be354d138841de649c89bacb9dee81e89fd4_S1.exe
Hancitor_Malware/f9efadc1f2ff65179f005704fafaf63b7d8f6d9bb6be3e08329126634df2d333_S1.exe
Hancitor_Malware/846fe7d28d9134a06a3de32d7a102e481824cca8155549c889fb6809aedcbc2c_S1.exe
Hancitor_Malware/0cb34a9c52755ec21ad7eda70aecb961b9751441df65f93a928bf48819c2f7ae_S1.exe
Hancitor_Malware/e7b3ef04c211fafa36772da62ab1d250970d27745182d0f3736896cf7673dc3a_S1.exe
Hancitor_Malware/1c72f575d0c9574afcfcaab7e0b89fe0083dbe8ac20c0132a978eb1f6be59641_S1.exe
Hancitor_Malware/a26ecd4859456cd36d7cf3b12e92e318a7922e88ccb1558753c796f2cb08408d_S1.exe
Hancitor_Malware/fff786ec23e6385e1d4f06dcf6859cc2ce0a32cee46d8f2a0c8fd780b3ecf89a_S1.exe
Hancitor_Malware/ae079ad161c473a383174b2badcc874da7c188f1df48deb8b9ac407b5238cb47_S1.exe
Hancitor_Malware/de800b6bb8268a59d281cd3a859837c75be4fff3af634dfc64b041753d60c00f_S1.exe
Hancitor_Malware/ab90ed6cb461f17ce1f901097a045aba7c984898a0425767f01454689698f2e9_S1.exe
Hancitor_Malware/f0420708c417376a52121f0a83c25a8b2051fffa5b3365205c34ac56e3d0065d_S1.exe
Hancitor_Malware/1c7f4150670158ab16e475f3641739d5adc40e191a64167f14c8c152be7fda82_S1.exe
Hancitor_Malware/40a8bb6e3eed57ed7bc802cc29b4e57360aa10c2de01d755f9577f07e10b848b_S1.exe
Hancitor_Malware/fed9cc2c7cfb97741470cb79c189a203545af88bdd67bc99e2d7499d343de653_S1.exe

BYTES:

558BEC83EC1C57FF750CFF7508E87E0000008BF883C40885FF7444568B770C8D45E40375086A1C5056FF156440400083F81C7523F645F844741D8B4F1033C085C97409803430A1403BC172F75EB8010000005F8BE55DC35E33C05F8BE55DC3B8010000005F8BE55DC3CCCCCCCCCCCCCC558BEC68BC424000FF7508E880FFFFFF4883C408F7D81BC0405DC3CCCCCCCCCC558BEC83EC108B45085356578B483C33FF03C80FB741148D51180FB7590603D08955F0895DF485DB74748B450C8BF28A08884D0B0FB6C983C9202BF0894DF88BCA894DFC8BD00FB60183C8202B45F875228A5D0B84DB74158A5A01420FB6CB83C9200FB6041683C8202BC174E78B4DFC8B5DF485C078047F0274134783C12883C628894DFC3BFB73158B450CEBB68B4DF08D04BF5F5E5B8D04C18BE55DC35F5E33C05B8BE55DC3CCCCCCCCCCCCCCCCCC558BEC8B45088BC881E1FF0F00002BC133C92D0010000080384D75068078015A74084183F9647CEA33C05DC3CCCCCCCC558BEC83EC18538B5D0833D2565733F68B433C8B44187803C38B481C8B782403CB894DE803FB8B482003CB897DF0894DF88B48188B4014894DF48945FC85C9746F0FBF04778945EC3BF173783B45FC73738B45F88B4D0C8BD18B3CB00FB6041F03FB8A1983C8200FB6CB83C9202BC1751B2BFA84DB74158A5A01420FB6CB83C9200FB6041783C8202BC174E785C078047F0274108B4DF4463BF1731D8B5D088B7DF0EB9D8B45EC8B55E88B14820355085F5E8BC25B8BE55DC35F33D25E8BC25B8BE55DC35F5E33C05B8BE55DC3CCCCCC5633C064A130000000780C8B400C8B701CAD8B4008EB098B40348D407C8B403C5EC3CCCCCCCCCCCCCCCCCCCCCCCCCCCC558BEC83EC108B4D085356578B793C03F9E8BAFFFFFF8BF0688C42400056E8DDFEFFFF8BD8689C42400056895DF0E8CDFEFFFF68AC424000568945FCE8BFFEFFFF8B55FC83C4188945F885DB750885D20F848A00000085C00F84820000008B87800000008B4D0803C18945F483780C00746E8B70108B3803F103F9833E0074518B1F8B400C03D903C18B4DF085C9740550FFD1EB0B85D274476A006A0050FFD28BC885C9743A8B0785C00FB7C078038D43025051FF55F83906740289068B45F483C6048B4D0883C7048B55FC833E0075AF8B55FC83C0148945F483780C0075925F5E5B8BE55DC3CCCCCCCCCCCCCCCCCC566860334000E8D5FDFFFF8BF056E8FDFEFFFF56E8F7FCFFFF83C40C5E85C07501C3E889ECFFFFCC000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

INFO:

binsequencer.py Hancitor_Malware/
Match SUCCESS for generic

*/

rule rule0
    {
        meta:
            description = "Autogenerated by Binsequencer v.1.0.4 from Hancitor_Malware/fff786ec23e6385e1d4f06dcf6859cc2ce0a32cee46d8f2a0c8fd780b3ecf89a_S1.exe"
            author      = ""
            date        = "2018-06-06"

        strings:
            $rule0_bytes = { 558B??83????57FF????FF????E8????????8B??83????85??74??568B????8D????03????6A??5056FF??????????83????75??F6??????74??8B????33??85??74??80??????403B??72??5EB8????????5F8B??5DC35E33??5F8B??5DC3B8????????5F8B??5DC3CCCCCCCCCCCCCC558B??68????????FF????E8????????4883????F7??1B??405DC3CCCCCCCCCC558B??83????8B????5356578B????33??03??0FB7????8D????0FB7????03??89????89????85??74??8B????8B??8A??88????0FB6??83????2B??89????8B??89????8B??0FB6??83????2B????75??8A????84??74??8A????420FB6??83????0FB6????83????2B??74??8B????8B????85??78??7F??74??4783????83????89????3B??73??8B????EB??8B????8D????5F5E5B8D????8B??5DC35F5E33??5B8B??5DC3CCCCCCCCCCCCCCCCCC558B??8B????8B??81??????????2B??33??2D????????80????75??80??????74??4183????7C??33??5DC3CCCCCCCC558B??83????538B????33??565733??8B????8B??????03??8B????8B????03??89????03??8B????03??89????89????8B????8B????89????89????85??74??0FBF????89????3B??73??3B????73??8B????8B????8B??8B????0FB6????03??8A??83????0FB6??83????2B??75??2B??84??74??8A????420FB6??83????0FB6????83????2B??74??85??78??7F??74??8B????463B??73??8B????8B????EB??8B????8B????8B????03????5F5E8B??5B8B??5DC35F33??5E8B??5B8B??5DC35F5E33??5B8B??5DC3CCCCCC5633??64??????????78??8B????8B????AD8B????EB??8B????8D????8B????5EC3CCCCCCCCCCCCCCCCCCCCCCCCCCCC558B??83????8B????5356578B????03??E8????????8B??68????????56E8????????8B??68????????5689????E8????????68????????5689????E8????????8B????83????89????85??75??85??0F84????????85??0F84????????8B??????????8B????03??89????83??????74??8B????8B??03??03??83????74??8B??8B????03??03??8B????85??74??50FF??EB??85??74??6A??6A??50FF??8B??85??74??8B??85??0FB7??78??8D????5051FF????39??74??89??8B????83????8B????83????8B????83????75??8B????83????89????83??????75??5F5E5B8B??5DC3CCCCCCCCCCCCCCCCCC5668????????E8????????8B??56E8????????56E8????????83????5E85??75??C3E8????????CC000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 }

        condition:
            all of them
}
```
