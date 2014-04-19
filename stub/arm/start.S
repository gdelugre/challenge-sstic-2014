	.arch armv7-a
	.text
	.globl _start
	.type _start,#function
_start:
	mov fp, #0
	mov lr, #0
	ldr r0, [sp], #4
	mov r1, sp
	b __init
