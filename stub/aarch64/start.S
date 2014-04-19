	.cpu generic
	.text
	.globl _start
	.type _start,#function
_start:
	mov x30, #0
	mov x29, sp
	ldr x0, [sp,#0]
	add x1, sp, #8
	b __init
