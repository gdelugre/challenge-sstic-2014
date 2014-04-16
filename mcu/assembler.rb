#!/usr/bin/env ruby

require 'openssl'

OPCODES = 
{
    'mov.lo' => 1,
    'mov.hi' => 2,
    'xor' => 3,
    'or' => 4,
    'and' => 5,
    'add' => 6,
    'sub' => 7,
    'mul' => 8,
    'div' => 9,
    'jz' => 10,
    'jnz' => 10,
    'js' => 10,
    'jns' => 10,
    'jmp' => 11,
    'call' => 12,
    'syscall' => 12,
    'ret' => 13,
    'sysret' => 13,
    'ldr' => 14,
    'str' => 15,
}

META = %w{ mov }

REGISTERS = (0..15).to_a.map{|i| "r#{i}"}
CONDITIONS = [ 'z', 'nz', 's', 'ns' ]
LABELS = {}

def encode_hex(prog)
    line_size = 16
    lines = Array.new((prog.size + line_size - 1) / line_size) { |n|
        data = prog[n * line_size, line_size]

        line = '%02X%04X00%s' % [ data.size, n * line_size, data.unpack('H*')[0].upcase ]
        cksum = -[line].pack('H*').bytes.inject(0, &:+) & 0xff

        ":#{line}%02X" % cksum
    } + [ ':00000001FF' ]

    lines.join($/)
end

def compute_labels(lst, base = 0)
    labels = {}
    lst.lines.map(&:chomp).map(&:strip).each do |line|
        next if line.empty?
        next if line[0] == ?#

        if line =~ /([[:graph:]]+):$/
            labels[$1] = base 
        elsif line =~ /^.data (.*)/
            items = $1.split(',').map(&:strip)
            data = encode_data(items)
            data += "\x00" if data.size % 2 == 1 # preserve alignment
            base += data.size
        elsif line =~ /^mov (.*)/ # meta instruction
            if REGISTERS.include?($1.split(',').map(&:strip).last)
                base += 2
            else
                base += 4
            end
        else
            base += 2
        end
    end

    LABELS.update(labels)
end

def reg(arg); REGISTERS.index(arg) & 0xf end
def cond(arg); CONDITIONS.index(arg) & 3 end
def addr(label); LABELS[label] or fail("Bad label #{label.inspect}") end

def encode_insn(pc, opcode, *args)
    fail "Unknown instruction: #{opcode.inspect}"unless OPCODES.include?(opcode) or META.include?(opcode)

    insn = (OPCODES[opcode] << 12) if OPCODES.include?(opcode)
    case opcode
        when 'mov' # meta
            if REGISTERS.include?(args[1])
                return encode_insn(pc, "and", args[0], args[1], args[1])
            else
                value = LABELS[args[1]] || args[1].hex
                return encode_insn(pc, "mov.hi", args[0], ((value >> 8) & 0xff).to_s(16)) + 
                       encode_insn(pc+2, "mov.lo", args[0], ((value & 0xff).to_s(16)))
            end

        when 'mov.lo', 'mov.hi'
            insn |= (reg(args[0]) << 8)
            insn |= (args[1].hex & 0xff) 
        when 'xor', 'or', 'and', 'add', 'sub', 'mul', 'div'
            insn |= reg(args[0]) << 8
            insn |= reg(args[1]) << 4
            insn |= reg(args[2]) << 0
        when /j(s|z|ns|nz)/
            insn |= cond($1) << 10
            insn |= (addr(args[0]) - (pc + 2)) & 1023
        when 'jmp', 'call'
            insn |= (addr(args[0]) - (pc + 2)) & 1023
        when 'syscall'
            insn |= (1 << 11) # syscall bit
            insn |= (args[0].hex)
        when 'ret'
            insn |= reg(args[0])
        when 'sysret'
            insn |= (1 << 11)
        when 'ldr', 'str'
            insn |= reg(args[0]) << 8
            insn |= reg(args[1]) << 4
            insn |= reg(args[2]) << 0
    end

    [ insn ].pack('n')
end

def encode_data(items)
    data = ''

    items.each do |item|
        if item[0] == '"' or item[0] == "'" and item[0] == item[-1]
            data += item[1..-2].gsub('\\\\','\\').gsub('\\"','"').gsub("\\'", "'").gsub("\\n", "\n")
        elsif LABELS.include?(item)
            data += LABELS[item].pack('n')
        else
            data += item.hex.chr
        end 
    end
    data
end

def assemble(lst, base = 0)
    compute_labels(lst, base)
    code = ''.force_encoding('binary')

    lst.lines.map(&:chomp).map(&:strip).each do |line|
        next if line.empty? or line[-1] == ?: or line[0] == ?#
        addr = base + code.size

        if line =~ /^.data (.*)/
            items = $1.split(',').map(&:strip)
            data = encode_data(items)
            data += "\x00" if data.size % 2 == 1 # preserve alignment
            code += data
        elsif line.count(' ') == 0
            opcode = line
            code += encode_insn(addr, opcode)
        elsif line =~ /^([^ ]+) (.*)$/
            opcode = $1
            args = $2.split(', ') 
            code += encode_insn(addr, opcode, *args)
        else
            fail "Cannot parse line: #{line.inspect}"
        end
    end

    code
end

SECRET_RC4_KEY = "YeahRiscIsGood!"
SUCCESS_STR = "Firmware execution completed in $$$$$ CPU cycles.\n"

kind = ARGV.empty? ? 'fw' : ARGV[0]
program = assemble(<<-LISTING) if kind == 'fw'
###
### SSTIC 2014, remote firmware
### 

mov r0, 0x1000
mov r1, secret_key
mov r2, #{SECRET_RC4_KEY.size.to_s(16)}
call rc4_initialize

mov r0, 0x1000
mov r1, goodbye_str
mov r2, #{SUCCESS_STR.size.to_s(16)}
call rc4_decrypt

mov r0, 0x1100
call read_tsc
call read_word

mov r10, r0

mov r1, #{"$".ord.to_s(16)}
mov r0, goodbye_str
call strchr

mov r1, r10
call to_dec

mov r1, #{SUCCESS_STR.size.to_s(16)}
mov r0, goodbye_str
call print

jmp halt

#
# rc4_initialize(void *state, char *key, int keylen);
#
rc4_initialize:
    mov r8, r0
    mov r9, r1
    mov r10, r2

    xor r0, r0, r0
    mov r1, 0x100
    mov r2, 1 

    .rc4_fill_state:
        sub r3, r1, r0
        jz .rc4_fill_state_done
        str r0, r8, r0
        add r0, r0, r2
        jmp .rc4_fill_state
    .rc4_fill_state_done:

    xor r0, r0, r0
    mov r1, r0
    mov r2, 1
    mov r3, 0xff

    .rc4_init_state:
        # j += S[i]
        ldr r4, r8, r0
        add r1, r1, r4

        # i - (i / len(secret)) * len(secret)
        div r4, r0, r10
        mul r4, r4, r10
        sub r4, r0, r4

        # j += secret[i % len(secret)] & 0xff
        ldr r4, r9, r4
        add r1, r1, r4
        and r1, r1, r3

        # S[i] <=> S[j]
        ldr r4, r8, r0
        ldr r5, r8, r1
        str r5, r8, r0
        str r4, r8, r1

        # i++
        add r0, r0, r2
        sub r4, r3, r0
    jns .rc4_init_state
    ret r15

#
# rc4_encrypt(void *state, void *buffer, int size);
#
rc4_encrypt:
    jmp rc4_cipher

#
# rc4_decrypt(void *state, void *buffer, int size);
#
rc4_decrypt:
    jmp rc4_cipher

#
# rc4_cipher(void *state, void *buffer, int size);
#
rc4_cipher:
    mov r8, r0
    mov r9, r1
    mov r10, r2

    xor r0, r0, r0
    mov r1, r0
    mov r2, r0
    mov r3, 0xff
    mov r4, 1

    .rc4_cipher_loop:
        # i = (i + 1) mod 256
        add r0, r2, r4
        and r0, r0, r3

        # j = (j + S[i]) mod 256
        ldr r5, r8, r0
        add r1, r1, r5
        and r1, r1, r3
        
        # S[i] <=> S[j]
        ldr r5, r8, r0
        ldr r6, r8, r1
        str r6, r8, r0
        str r5, r8, r1

        # S[S[i] + S[j] mod 256]
        add r5, r5, r6
        and r5, r5, r3
        ldr r5, r8, r5

        # XOR with keystream
        ldr r6, r9, r2
        xor r6, r6, r5
        str r6, r9, r2

        add r2, r2, r4
        sub r5, r10, r2
    jnz .rc4_cipher_loop
    ret r15 

# halt(void)
halt:
    syscall 1
    jmp halt

# print(char *);
print:
    syscall 2
    ret r15

# read_tsc(int *);
read_tsc:
    syscall 3
    ret r15

# read_word(int *);
read_word:
    mov r1, 1
    mov r2, 0x100
    ldr r3, r0, r1
    sub r1, r1, r1
    ldr r4, r0, r1
    mul r4, r4, r2
    or r0, r3, r4
    ret r15

# strchr(char *, char);
strchr:
    xor r2, r2, r2
    mov r3, 1
    .strchr_loop:
        xor r4, r4, r4
        ldr r4, r0, r2
        and r4, r4, r4
        jz .strchr_not_found
        sub r4, r4, r1 
        jz .strchr_end
        add r0, r0, r3
        jmp .strchr_loop
    .strchr_not_found:
    xor r0, r0, r0
    .strchr_end:
    ret r15

# to_hex(char *, int)
to_hex:
    mov r4, 0x1000
    mov r5, 0xf
    mov r6, 0xa
    mov r7, 1

    .to_hex_next_digit:
    div r2, r1, r4
    and r2, r2, r5
    sub r3, r2, r6
    js .to_hex_num
        mov r3, 0x37
        jmp .hex_write
    .to_hex_num:
        mov r3, 0x30
    .hex_write:
    add r2, r3, r2
    xor r3, r3, r3
    str r2, r0, r3
    add r0, r0, r7
    sub r2, r4, r7
    jz .to_hex_end

    add r3, r5, r7    
    div r4, r4, r3
    jmp .to_hex_next_digit

    .to_hex_end:
    ret r15

# to_dec(char *, int)
to_dec:
    mov r4, 0x2710
    mov r5, 0xa
    xor r6, r6, r6
    mov r7, 1
    sub r0, r0, r7

    .to_dec_next_digit:
    add r0, r0, r7
    div r2, r1, r4
    mul r3, r2, r4
    sub r1, r1, r3
    div r4, r4, r5
    mov r8, 0x20
    xor r3, r3, r3
    str r8, r0, r3
    or r6, r6, r2
    jz .to_dec_next_digit
    mov r8, 0x30 
    add r8, r8, r2
    str r8, r0, r3
    and r4, r4, r4
    jnz .to_dec_next_digit
    ret r15

secret_key:
    .data #{SECRET_RC4_KEY.inspect}, 0

goodbye_str:
    .data #{
        rc4 = OpenSSL::Cipher::RC4.new.encrypt
        rc4.key_len = SECRET_RC4_KEY.length 
        rc4.key = SECRET_RC4_KEY
        (rc4.update(SUCCESS_STR) + rc4.final).bytes.map{|c| c.to_s(16)}.join(",")
    }, 0
LISTING

program = assemble(<<-LISTING) if kind == 'xp'
###
### SSTIC 2014, remote exploit
### 

mov r0, 0x1000
xor r1, r1, r1
xor r2, r2, r2
mov r3, 1 
mov r4, 0x200

loop:
    and r0, r0, r0
    str r1, r0, r2
    add r2, r2, r3
    sub r5, r4, r2
    jnz loop

mov r0, 0xF000
syscall 3

mov r0, 0x10F2
mov r1, shellcode
mov r2, 0x100
call memcpy

# Gives code execution at 0x10F2
syscall 1

memcpy:
    mov r3, 1
    .memcpy_loop:
    sub r2, r2, r3
    js .memcpy_end 
    ldr r4, r1, r2 
    str r4, r0, r2
    jmp .memcpy_loop
    .memcpy_end:
    ret r15

shellcode:
    mov r0, 0xF008
    mov r8, 0xFC00
    mov r1, 0xBF8
    xor r2, r2, r2
    mov r4, 1

    .sc_loop:
        ldr r3, r0, r2
        xor r9, r9, r9
        str r3, r8, r9
        add r2, r2, r4
        sub r5, r1, r2
        jnz .sc_loop

.data 0, 0
LISTING

program = assemble(<<-LISTING) if kind == 'dump'
###
### SSTIC 2014, remote ROM dumper.
###
mov r0, 0xFD00
mov r1, 0x300
syscall 2
syscall 1
LISTING

program = assemble(<<-LISTING, 0xFD00) if kind == 'rom'
#
# ROM code. Base is 0xFD00.
#
and r0, r0, r0
jz reset

mov r1, 3
sub r2, r1, r0
js unknown_syscall

mov r2, 2
mul r1, r0, r2
sub r1, r1, r2
mov r0, 0xF000
add r0, r0, r1
call read_word
ret r0

unknown_syscall:
    mov r1, #{"[ERROR] Undefined system call. CPU halted.\n".size.to_s(16)}
    mov r0, error_bad_syscall
    call print

# halt(void);
system_call_halt:
    xor r0, r0, r0
    mov r1, 0xFC10
    mov r2, 1
    str r2, r1, r0
    jmp system_call_halt

# print(char *);
system_call_print:
    mov r0, 0xFC22
    call read_word
    mov r5, r0   
    mov r0, 0xFC20
    call read_word
    mov r1, r5
    call print
    sysret

# read_tsc(int *);
system_call_read_tsc:
    mov r0, 0xFC20
    call read_word
    mov r6, 0xFC12
    mov r1, 1
    xor r4, r4, r4
    .loop_tsc:
        ldr r5, r6, r1
        ldr r2, r6, r4
        ldr r3, r6, r4
        sub r3, r3, r2
        jnz .loop_tsc
    mov r3, 0x100
    mul r2, r2, r3
    or r1, r2, r5
    call write_word
    sysret

reset:
    mov r1, #{"System reset.\n".size.to_s(16)}
    mov r0, reset_msg
    call print

    # Install syscall handlers
    mov r4, 2
    mov r1, system_call_halt
    mov r0, 0xF000
    call write_word
    add r0, r0, r4
    mov r1, system_call_print
    call write_word
    add r0, r0, r4
    mov r1, system_call_read_tsc
    call write_word
    
    # Clear context
    mov r0, 0xFC20
    xor r1, r1, r1
    mov r2, 36
    call memset

    # Set stack pointer
    mov r0, 0xFC3A
    mov r1, 0xEFFE
    call write_word
    sysret

# read_word(int *);
read_word:
    mov r1, 1
    mov r2, 0x100
    ldr r3, r0, r1
    sub r1, r1, r1
    ldr r4, r0, r1
    mul r4, r4, r2
    or r0, r3, r4
    ret r15

# write_word(int *, int);
write_word:
    mov r2, 1
    mov r3, 0x100
    str r1, r0, r2
    sub r2, r2, r2
    div r1, r1, r3
    str r1, r0, r2
    ret r15

# memset(void *, char, int);
memset:
    mov r3, 1
    and r2, r2, r2  
    jz .memset_end
    sub r2, r2, r3
    str r1, r0, r2
    jmp memset
    .memset_end:
    ret r15
    
#
# print(char *);
#
print:
    mov r14, r0
    mov r13, 0xFC00
    mov r12, 0xF000
    xor r8, r8, r8
    mov r9, r8
    mov r10, 1
    xor r11, r11, r11

    .print_loop: 
        and r1, r1, r1
        jz .print_ret
        add r9, r14, r8
        sub r9, r9, r12
        js .allowed_addr
        add r9, r14, r8
        sub r9, r9, r13
        jns .allowed_addr
        jmp exit_bad_addr
    .allowed_addr:
        xor r9, r9, r9
        ldr r9, r14, r8
        str r9, r13, r11
        add r8, r8, r10
        sub r1, r1, r10
        jmp .print_loop
    .print_ret:
    ret r15

exit_bad_addr:
    mov r1, #{"[ERROR] Printing at unallowed address. CPU halted.\n".size.to_s(16)}
    mov r0, error_bad_addr
    call print
    jmp system_call_halt

error_bad_addr:
    .data "[ERROR] Printing at unallowed address. CPU halted.\\n", 0

error_bad_syscall:
    .data "[ERROR] Undefined system call. CPU halted.\\n", 0

reset_msg:
    .data "System reset.\\n",0
LISTING

if kind == 'fw'
    puts hex = encode_hex(program)
    File.binwrite("fw.hex", hex)
elsif kind == 'xp'
    puts hex = encode_hex(program)
    File.binwrite('exploit.hex', hex)
elsif kind == 'dump'
    puts hex = encode_hex(program)
    File.binwrite('dump_rom.hex', hex)
else
    File.binwrite("rom.bin", program)
end

