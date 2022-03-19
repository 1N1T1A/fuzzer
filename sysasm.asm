_TEXT$00 segment para 'CODE'

	ALIGN 16
	PUBLIC ntSyscallGate

; param 1 (rcx) service ID
; param 2 (rdx) service arguments count
; param 3 (r8) pointer to array of arguments

ntSyscallGate PROC
	cmp rdx, 5
	jl @@nostack
	
	sub rdx, 4
	xor r9, r9
@@fillstack:
	mov rax,[r9*8+r8+020h]
	mov [r9*8+rsp+028h], rax
	inc r9
	dec rdx
	jne @@fillstack

@@nostack:
	mov r10, r8
	mov rax, rcx
	mov rcx, [r10]
	mov rdx, [r10+08h]
	mov r8, [r10+10h]
	mov r9, [r10+18h]
	mov r10, rcx
	syscall
	ret
ntSyscallGate ENDP

_TEXT$00 ENDS
	
END
