#!/usr/bin/env ruby

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
    'ret' => 13,
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

def compute_labels(lst)
    base = 0
    labels = {}
    lst.lines.map(&:chomp).map(&:strip).each do |line|
        next if line.empty?
        next if line[0] == ?#

        if line =~ /(\w+):$/
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
            insn |= (addr(args[0]) - pc) & 1023
        when 'jmp', 'call'
            insn |= (addr(args[0]) - pc) & 1023
        when 'ret'
            insn |= reg(args[0])
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
        else
            data += item.hex.chr
        end 
    end
    data
end

def assemble(lst)
    compute_labels(lst)
    code = ''.force_encoding('binary')

    lst.lines.map(&:chomp).map(&:strip).each do |line|
        next if line.empty? or line[-1] == ?: or line[0] == ?#
        addr = code.size

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

program = assemble(<<-LISTING)
###
### SSTIC 2014, remote firmware
### 

xor r0, r0, r0

#
# RC4 implementation
#
mov r8, 0x1000
mov r9, 0x100
xor r1, r1, r1
mov r2, 1

rc4_init_state:
    sub r15, r9, r1
    jz rc4_init_state_done
    str r1, r8, r1
    add r1, r1, r2
    jmp rc4_init_state
rc4_init_state_done:

xor r1, r1, r1
mov r2, r1
mov r9, 0xff
mov r10, secret_key
mov r11, #{SECRET_RC4_KEY.size.to_s(16)}
mov r4, 1

rc4_init_state2:
    # j += S[i]
    ldr r5, r8, r1
    add r2, r2, r5

    # i - (i / len(secret)) * len(secret)
    div r5, r1, r11
    mul r5, r5, r11
    sub r5, r1, r5

    # j += secret[i % len(secret)] & 0xff
    ldr r5, r10, r5
    add r2, r2, r5
    and r2, r2, r9

    # S[i] <=> S[j]
    ldr r3, r8, r1
    ldr r5, r8, r2
    str r5, r8, r1
    str r3, r8, r2

    # i++
    add r1, r1, r4 
    sub r15, r9, r1
jns rc4_init_state2

xor r1, r1, r1
mov r2, r1
mov r3, r1
mov r9, 0x400
mov r10, 0xF800
mov r11, 0xff
mov r4, 1

rc4_cipher_loop:
    # i = (i + 1) mod 256
    add r1, r3, r4
    and r1, r1, r11

    # j = (j + S[i]) mod 256
    ldr r5, r8, r1
    add r2, r2, r5
    and r2, r2, r11
    
    # S[i] <=> S[j]
    ldr r5, r8, r1
    ldr r6, r8, r2
    str r6, r8, r1
    str r5, r8, r2

    # S[S[i] + S[j] mod 256]
    add r5, r5, r6
    and r5, r5, r11
    ldr r5, r8, r5

    # XOR with keystream
    ldr r6, r10, r3
    xor r6, r6, r5
    str r6, r10, r3

    add r3, r3, r4
    sub r15, r9, r3
jnz rc4_cipher_loop

mov r0, 0xF800
call print

mov r0, goodbye_str
call print

end:
    xor r0, r0, r0
    mov r1, 0xFC10
    mov r2, 1
    str r2, r1, r0
    jmp end

#
# print(char *);
#
print:
    mov r14, r0
    mov r13, 0xFC00
    xor r8, r8, r8
    mov r9, r8
    mov r10, 1
    xor r11, r11, r11

    print_loop: 
        ldr r9, r14, r8
        and r9, r9, r9
        jz print_ret
        str r9, r13, r11
        add r8, r8, r10
        jmp print_loop
    print_ret:
    ret r15

# arg0: state, arg1: key, arg2: keylen
#rc4_initialize:

secret_key:
    .data #{SECRET_RC4_KEY.inspect}, 0

goodbye_str:
    .data "Firmware successfully uploaded.\\n",0

LISTING

puts hex = encode_hex(program)
File.binwrite('fw.hex', hex)

