extern go
global alignstack

segment .text
alignstack:
    push rsi
    mov rsi, rsp
	push rdx
	push rcx
	mov rdx, 9999999999999999h
	mov rcx, 8888888888888888h	
    and  rsp, 0FFFFFFFFFFFFFFF0h 
    sub  rsp, 020h
    call go
	pop rcx
	pop rdx
    mov rsp, rsi
    pop rsi   
    ret   
