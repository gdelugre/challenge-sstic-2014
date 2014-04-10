#!/usr/bin/env ruby

exit(1) if ARGV.empty?

NUM_PAGES = (1 << 10)
OUTPUT_FILE = ARGV[0]
PROGRAM_SIZE = NUM_PAGES * 64

LABELS = {}

OPCODE_TABLE = %w{
    movi 
    ori 
    ldr 
    ldrh 
    ldrb 
    str 
    strh 
    strb 
    bcc 
    not 
    xor 
    or 
    and 
    lsl 
    lsr 
    asr 
    rol 
    ror 
    add 
    sub 
    mul 
    div 
    inc 
    dec 
    push 
    pop 
    ret 
    nop 
    hlt 
    sys
    par
}.each_with_index.to_h
  
REGISTERS = %w{R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R13 R14 R15}
CONDITIONS = %w{al nev eqz neqz ltz gtz ltez gtez}

CODE_BASE_ADDR = 64
STACK_BASE_ADDR = 0x2000
PAYLOAD_FILE = 'mcu_programmer.zip'
PAYLOAD_BASE_ADDR = 0x8000
PAYLOAD_SIZE = 0x2000
PAYLOAD_OUTPUT_FILE = "payload.bin"

#LFSR_SEED = 0x1111111111111111
LFSR_SEED = 0x05B1AD0B11ADDE15
LFSR_POLY = 0xB000000000000001
LFSR_SIZE = 64

def parity(n)
    n.to_s(2).count('1') & 1
end

def lfsr_encrypt(data)
    state = LFSR_SEED
    data = data.unpack('C*')

    byte = 0
    (data.size * 8).times do |i|
        state = (state >> 1) | (parity(state & LFSR_POLY) << (LFSR_SIZE - 1))

        byte |= (state & 1) << (7 - (i % 8))
        if (i % 8) == 7
            data[i / 8] ^= byte
            byte = 0
        end
    end

    data.pack('C*')
end

UNPADDED_PAYLOAD_SIZE = File.size(PAYLOAD_FILE)
fail "Payload is too big!" if UNPADDED_PAYLOAD_SIZE > PAYLOAD_SIZE
payload = File.binread(PAYLOAD_FILE).ljust(PAYLOAD_SIZE, "\x00")
payload[UNPADDED_PAYLOAD_SIZE,1] = "\x80".force_encoding('binary')

PAYLOAD = lfsr_encrypt(payload)

def get_insn_size(opcode)
    case opcode.downcase
    when 'mov' then 8
    when 'movr', 'movi', 'ori', /^ld.*/, /^st.*/, /^bl?\..*/ then 4
    else 2
    end
end

def reg(arg); REGISTERS.index(arg) & 0xf end
def cond(arg); CONDITIONS.index(arg) & 7 end
def addr(label); LABELS[label] or fail("Bad label #{label.inspect}") end

def encode_insn(opcode, *args)
    opcode.downcase!

    if opcode == 'mov'
        value = LABELS[args[1]] || args[1].hex
        return encode_insn("movi", args[0], ((value >> 16) & 0xffff).to_s(16)) + 
            encode_insn("ori", args[0], ((value & 0xffff).to_s(16)))
    elsif opcode == 'movr'
        return encode_insn("xor", args[0], args[0]) +
            encode_insn("or", args[0], args[1])
    end

    if opcode =~ /^bl?\..*/
        opc = OPCODE_TABLE['bcc']
    else
        fail "Bad opcode #{opcode}" unless OPCODE_TABLE.include?(opcode)
        opc = OPCODE_TABLE[opcode]
    end

    case opcode
    when 'movi', 'ori'
        rd = reg(args[0])
        imm = args[1].hex
        [ opc | (rd << 8) | (imm << 12) ].pack 'V'
    when /^ld.*/, /^st.*/
        rd = reg(args[0])
        rs = reg(args[1])
        off = args[2].to_i
        [ opc | (rd << 8) | (rs << 12) | (off << 16) ].pack 'V'
    when /^b.*/
        link = (opcode[1] == 'l') ? 1 : 0
        start = 2 + link
        rc = reg(args[0])
        cond = cond(opcode[start .. -1])
        dest = addr(args[1]) 
        [ opc | (link << 8) | (rc << 9) | (cond << 13) | (dest << 16) ].pack 'V'
    when 'not', 'inc', 'dec', 'push', 'pop'
        rd = reg(args[0])
        [ opc | (rd << 8) ].pack 'v'
    when 'xor', 'or', 'and', 'add', 'sub', 'mul', 'div', 'lsl', 'asr', 'lsr', 'rol', 'ror', 'par'
        rd = reg(args[0])
        rs = reg(args[1])
        [ opc | (rd << 8) | (rs << 12) ].pack 'v'
    when 'sys', 'ret', 'nop', 'hlt'
        [ opc ].pack 'v' 
    else
        fail "Do not know how to assemble #{opcode}"
    end
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

def compute_labels(prog, base = 0)
    labels = {}
    prog.lines.map(&:chomp).map(&:strip).each do |line|
        next if line.empty?
        next if line[0] == ?#

        if line =~ /([[:graph:]]+):$/
            labels[$1] = base
        elsif line =~ /^\.data (.*)/
            items = $1.split(',').map(&:strip)
            data = encode_data(items)
            data += "\x00" if data.size % 2 == 1 # preserve alignment
            base += data.size
        else
            base += get_insn_size(line.split(' ').first)
        end
    end

    LABELS.update(labels)
end

def assemble(lst, base = 0)
    compute_labels(lst, base)
    code = ''.force_encoding('binary')

    lst.lines.map(&:chomp).map(&:strip).each do |line|
        next if line.empty? or line[-1] == ?: or line[0] == ?#
        line.gsub!(/\s+\#.*$/,"")
        addr = base + code.size

        if line =~ /^.data (.*)/
            items = $1.split(',').map(&:strip)
            data = encode_data(items)
            data += "\x00" if data.size % 2 == 1 # preserve alignment
            code += data
        elsif line.count(' ') == 0
            opcode = line
            code += encode_insn(opcode) 
        elsif line =~ /^([^ ]+) (.*)$/ 
            opcode = $1
            args = $2.split(', ')
            code += encode_insn(opcode, *args)
        else
            fail "Bad assembly line : #{line.inspect}"
        end

    end

    code
end


@bytecode = assemble(<<ASM, CODE_BASE_ADDR)
#
# SSTIC, crack-me assembly routine.
#
MOV R1, 2
MOV R2, 1
MOV R3, prompt
MOV R4, #{":: Please enter the decryption key: ".size.to_s 16}
SYS

# Retrieve the key in hexstr format
MOV R1, 1
XOR R2, R2
MOV R3, input
MOV R4, 0x10
SYS

MOVR R5, R1

#MOV R1, 0x1337
#SYS

# dump input
#MOV R1, 0xdead
#MOV R2, input
#MOV R3, 0x10
#SYS

# We need 15 bytes
MOV R3, 0x10
SUB R5, R3
B.NEQZ R5, fail_wrong_pass

MOV R15, 0x10  # Counter
MOV R14, input # Current input

MOV R13, key   # Current output
DEC R13

MOV R2, 0x30   # '0' character
MOV R3, 0x39   # '9' character
MOV R4, 0x41   # 'A' character
MOV R5, 0x46   # 'F' character

loop:
    # For each character in input
    LDRB R12, R14, 0  # Get input

    # if cur_input < '0', goto end
    MOVR R1, R12
    SUB R1, R2
    B.LTZ R1, fail_wrong_pass

    # if cur_input <= '9', goto char_is_09
    MOVR R1, R12
    SUB R1, R3
    B.LTEZ R1, char_is_09

    # if cur_input < 'A', goto end
    MOVR R1, R12
    SUB R1, R4
    B.LTZ R1, fail_wrong_pass

    # If cur_input > 'F', goto end
    MOVR R1, R12
    SUB R1, R5
    B.GTZ R1, fail_wrong_pass

    char_is_AF:
    SUB R12, R4
    MOV R1, 0xA
    ADD R12, R1
    B.al R0, copy_nibble

    char_is_09:
    SUB R12, R2

    copy_nibble:
    MOV R7, 0x10
    SUB R7, R15
    MOV R1, 1
    AND R1, R7
    B.neqz R1, skip_shift

    MOV R7, 4
    LSL R12, R7
    INC R13 
    #B.al R0, skip_shift

    #odd_nibble:

    skip_shift:

    LDRB R1, R13, 0
    OR R1, R12
    STRB R1, R13, 0

    next:

    INC R14

    DEC R15
    B.NEQZ R15, loop

#MOV R1, 0xdead
#MOV R2, key
#MOV R3, 8
#SYS

MOV R1, 2
MOV R2, 1
MOV R3, decrypting
MOV R4, #{":: Trying to decrypt payload...\n".size.to_s(16)}
SYS

MOV R1, key
LDR R10, R1, 0
LDR R11, R1, 4

#MOV R1, 0x1337
#SYS

#
# The password is now loaded in R10, R11.
#

XOR R1, R1
MOV R2, #{PAYLOAD_BASE_ADDR.to_s(16)}
MOV R3, 8
XOR R4, R4

# 64 bits LFSR taps.
#
MOV R12, 0xB0000000
MOV R13, 0x00000001

lfsr_next:
    # Load state into R8, R9
    MOVR R8, R10
    MOVR R9, R11
    AND R8, R12
    AND R9, R13

    # Parity bit is saved in R9.
    XOR R8, R9
    PAR R9, R8

    # Update internal state.
    MOV R8, 1
    MOV R7, 0x1f

    MOVR R6, R10
    AND R6, R8
    LSL R6, R7
    LSR R11, R8
    OR R11, R6
    LSR R10, R8
    LSL R9, R7
    OR R10, R9

    # Extract output bit.
    DEC R3
    MOVR R7, R11
    AND R7, R8
    LSL R7, R3
    OR R4, R7

    B.NEQZ R3, lfsr_continue

    # Commit byte in memory.
    MOV R7, #{PAYLOAD_BASE_ADDR.to_s(16)}
    ADD R7, R1
    LDRB R8, R7, 0

#MOVR R2, R1
#MOV R1, 0x1337
#SYS
#MOV R1, 0x42
#SYS
#MOVR R1, R2

    XOR R8, R4
    STRB R8, R7, 0

    MOV R3, 8
    INC R1 # Increment byte counter
    XOR R4, R4

lfsr_continue:
    MOV R8, #{PAYLOAD_SIZE.to_s(16)}
    SUB R8, R1
    B.GTZ R8, lfsr_next

#
# Buffer decrypted. Now removes padding.
#
MOV R13, #{PAYLOAD_BASE_ADDR.to_s(16)}
MOV R12, #{PAYLOAD_SIZE.to_s 16}
MOV R11, 0x80
XOR R10, R10
MOV R9, 8

padding_strip_zeros:
    INC R10
    DEC R12
    B.LTEZ R12, fail_bad_padding 

    MOVR R10, R13
    ADD R10, R12
    LDRB R1, R10, 0
    B.eqz R1, padding_strip_zeros
    SUB R1, R11
    B.neqz R1, fail_bad_padding 
    SUB R10, R9
    B.ltez R10, fail_bad_padding
   
dump_file:
    # open()
    AND R1, R0
    MOV R2, filename
    MOV R3, 0x241
    MOV R4, #{0666.to_s 16}
    SYS

    B.LTZ R1, end

    # write()
    MOVR R2, R1
    MOV R1, 2
    MOV R3, #{PAYLOAD_BASE_ADDR.to_s(16)}
    MOVR R4, R12 
    SYS

    # close()
    MOV R1, 3
    SYS

    MOV R1, 2
    MOV R2, 1
    MOV R3, success
    MOV R4, #{":: Decrypted payload written to #{PAYLOAD_OUTPUT_FILE}.\n".size.to_s(16)}
    SYS
    B.AL R0, end


end:
    HLT

fail_wrong_pass:
    MOV R1, 2
    MOV R2, 2
    MOV R3, bad_pass 
    MOV R4, #{"   Wrong key format.\n".size.to_s 16}
    SYS
    B.AL R0, end

fail_bad_padding:
    MOV R1, 2
    MOV R2, 2
    MOV R3, bad_padding
    MOV R4, #{"   Invalid padding.\n".size.to_s 16}
    SYS
    B.AL R0, end

open_failed:
    MOV R1, 2
    MOV R2, 2
    MOV R3, open_failure
    MOV R4, #{"   Cannot open file #{PAYLOAD_OUTPUT_FILE}.\n".size.to_s(16)}
    SYS
    B.AL R0, end

key:
    .data 0,0,0,0,0,0,0,0

prompt:
    .data ":: Please enter the decryption key: ",0

decrypting:
    .data ":: Trying to decrypt payload...", 0xa

bad_pass:
    .data "   Wrong key format.",0xa,0

bad_padding:
    .data "   Invalid padding.",0xa,0

open_failure:
    .data "   Cannot open file #{PAYLOAD_OUTPUT_FILE}.",0xa,0

success:
    .data ":: Decrypted payload written to #{PAYLOAD_OUTPUT_FILE}.",0xa,0

filename:
    .data "#{PAYLOAD_OUTPUT_FILE}",0

input:
    .data "XXXXXXXXXXXXXXXX", 0
ASM

@bytecode = "\x00" * 64 + @bytecode
@bytecode[0x34,4] = [ STACK_BASE_ADDR ].pack 'V'
@bytecode[0x3c,4] = [ 0x40 ].pack 'V'
@bytecode = @bytecode.ljust(PROGRAM_SIZE, "\x00")
@bytecode[PAYLOAD_BASE_ADDR, PAYLOAD_SIZE] = PAYLOAD

File.binwrite(OUTPUT_FILE, @bytecode)

__END__
system "./chacha_crypt #{PROGRAM_BIN}"

@bytecode = File.binread PROGRAM_BIN

File.open(PROGRAM_HDR, 'w') do |fd|
    fd.puts "#ifndef __H_BYTECODE"
    fd.puts "#define __H_BYTECODE"
    fd.puts
    fd.puts "unsigned char vm_bytecode[] = {"
    fd.write " " * 4

    i = 0
    @bytecode.each_byte { |byte|
        fd.write("0x%02x, " % byte)
        fd.write("\n    ") if i % 16 == 15
        i += 1
    }

    fd.puts "};"
    fd.puts
    fd.puts "#endif"
end

