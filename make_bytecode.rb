#!/usr/bin/env ruby

exit(1) if ARGV.empty?

OUTPUT_FILE = ARGV[0]
PROGRAM_SIZE = 8192 * 64

LABELS = {}

OPCODE_TABLE = {
    'HALT' => 0,
    'NONE' => 1,
    'LDRB' => 2,
    'LDRH' => 3,
    'LDRW' => 4,
    'LDR' => 5,
    'STRB' => 6,
    'STRH' => 7,
    'STRW' => 8,
    'STR' => 9,
    'MOV_IMM19' => 10,
    'SHL' => 11,
    'SHR' => 12,
    'ADD' => 13,
    'SUB' => 14,
    'AND' => 15,
    'OR' => 16,
    'XOR' => 17,
    'NOT' => 18,
    'CMP' => 19,
    'BR' => 20,
    'PRINT' => 21,
    'READLN' => 22,
    'WRITEFILE' => 23,
}

REGISTERS = %w{R0 R1 R2 R3 R4 R5 R6 PC}

STRINGS = [
    "Please enter the password: ",
    "Dumping payload...\n",
    "Wrong password.\n",
    "payload.bin"
]

CONSTS =
[
    1,
    16,
    '0'.ord,
    '9'.ord,
    'a'.ord,
    'f'.ord,
    4,
    64
]

@rodata_base = nil
@rodata_size = 0
@consts_base = nil
@consts_size = 0

CODE_BASE_ADDR = 64
BSS_BASE_ADDR = 32 * 4096
RODATA_BASE_ADDR = 64 * 4096

def encode_insn(opcode, *args)
    cond = 0
    if opcode[-2,2] == "EQ"
        cond = 1
        opcode = opcode[0..-3]
    elsif opcode[-2,2] == "LO"
        cond = 2
        opcode = opcode[0..-3]
    elsif opcode[-2,2] == "HI"
        cond = 3
        opcode = opcode[0..-3]
    end

    if opcode == 'MOV'
        if args.last =~ /[0-9]+/
            opcode = 'MOV_IMM19'
        elsif REGISTERS.include?(args.last)
            opcode = 'LDR'
            args[1] = REGISTERS.index(args[1]) * 8
        else
            fail "Bad MOV : #{args.inspect}"
        end
    end

    fail "Bad opcode #{opcode}" unless OPCODE_TABLE.include?(opcode)
    opc = OPCODE_TABLE[opcode]
    reg = 0
    addr = 0

    case opcode
    when /^LDR/, /^STR/
        fail "bad ldr/str"if args.length > 2
        reg = REGISTERS.index(args[0])
        addr = REGISTERS.index(args[1])
    when 'MOV_IMM19'
        reg = REGISTERS.index(args[0])
        addr = args[1].to_i
    when 'SHL', 'SHR', 'ADD', 'SUB', 'AND', 'OR', 'XOR', 'CMP'
        reg = REGISTERS.index(args[0])
        if REGISTERS.include?(args[1])
            addr = REGISTERS.index(args[1]) * 8
        else
            addr = args[1].to_i
        end
    when 'NOT'
        reg = REGISTERS.index(args[0])
    when 'BR'
        addr = LABELS[args[0]]
    when 'PRINT', 'READLN', 'WRITEFILE'
        addr = args[0].to_i
    end
    
    [ opc | (reg << 8) | (addr << 11) | (cond << 30) ].pack 'V'
end

def install_rodata(bytecode)
    @rodata_base = RODATA_BASE_ADDR

    rodata = STRINGS.join('') 
    bytecode[@rodata_base, rodata.size] = rodata

    @rodata_size = rodata.size
end

def install_consts(bytecode)
    @consts_base = @rodata_base + @rodata_size 
    consts = CONSTS.pack 'Q*'
    bytecode[@consts_base, consts.size] = consts

    @consts_size = consts.size
end

def reg_addr(r)
    REGISTERS.index(r) * 8
end

def str_addr(string)
    fail unless STRINGS.include?(string)

    base = RODATA_BASE_ADDR 
    STRINGS.each do |str|
        break if str == string
        base += str.size
    end

    base.to_s
end

def const_addr(c)
    fail unless CONSTS.include?(c)

    base = @consts_base
    CONSTS.each do |co|
        break if co == c
        base += 8
    end

    base.to_s
end

def compute_labels(prog)
    base = CODE_BASE_ADDR
    prog.lines.map(&:chomp).map(&:strip).each do |line|
        next if line.empty?
        next if line[0] == ?#

        if line =~ /(\w+):$/
            LABELS[$1] = base
        else
            base += 4
        end
    end
end

def assemble(bytecode, prog)
    compute_labels(prog)
    base = CODE_BASE_ADDR
    prog.lines.map(&:chomp).map(&:strip).each do |line|
        next if line.empty? or line[-1] == ?: or line[0] == ?#

        if line.count(' ') == 0
            opcode = line
            bytecode[base, 4] = encode_insn(opcode) 
        elsif line =~ /^([^ ]+) (.*)$/ 
            opcode = $1
            args = $2.split(', ')
            bytecode[base, 4] = encode_insn(opcode, *args)
        else
            fail "Bad assembly line : #{line.inspect}"
        end

        base += 4
    end

    bytecode
end


bytecode = "\x00" * PROGRAM_SIZE
install_rodata(bytecode)
install_consts(bytecode)

@bytecode = assemble(bytecode, <<ASM)
#
# SSTIC, crack-me assembly routine.
#
MOV R0, #{"Please enter the password: ".size}
PRINT #{str_addr("Please enter the password: ")}

READLN #{BSS_BASE_ADDR}
CMP R0, #{const_addr(16)}
BRLO failure
BRHI failure

XOR R1, R1
XOR R3, R3

check_chars:
    CMP R1, R0
    BREQ dump

    MOV R2, #{BSS_BASE_ADDR}
    ADD R2, R1
    LDRB R2, R2
    CMP R2, #{const_addr('0'.ord)}
    BRLO failure
    CMP R2, #{const_addr('f'.ord)}
    BRHI failure
    CMP R2, #{const_addr('a'.ord)}
    BRLO check_num
    SUB R2, #{const_addr('a'.ord)}
    BR next_char
check_num:
    CMP R2, #{const_addr('9'.ord)}
    BRHI failure
    SUB R2, #{const_addr('0'.ord)}

next_char:
    SHL R3, #{const_addr(4)}
    OR R3, R2
    ADD R1, #{const_addr(1)}
    BR check_chars

dump:
    MOV R0, #{"Dumping payload...\n".size}
    PRINT #{str_addr("Dumping payload...\n")}

    MOV R2, 64
    XOR R1, R1
    MOV R0, #{"payload.bin".size}
    WRITEFILE #{str_addr("payload.bin")}

BR end

failure:
    MOV R0, #{"Wrong password.\n".size}
    PRINT #{str_addr("Wrong password.\n")}

end:
HALT
ASM

@bytecode[0x38,8] = [ 0x40 ].pack 'Q'

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

