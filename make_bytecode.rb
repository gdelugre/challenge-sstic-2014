#!/usr/bin/env ruby

PROGRAM_HDR = "vm_bytecode.h"
PROGRAM_BIN = "vm_bytecode.bin"
PROGRAM_SIZE = 8192 * 64

OPCODE_TABLE = {
    'HALT' => 0,
    'NONE' => 1,
    'LDR' => 2,
    'STR' => 3,
    'MOV_IMM19' => 4,
    'SHL' => 5,
    'SHR' => 6,
    'ADD' => 7,
    'SUB' => 8,
    'AND' => 9,
    'OR' => 10,
    'XOR' => 11,
    'NOT' => 12,
    'CMP' => 13,
    'BR' => 14,
    'PRINT' => 15,
    'READLN' => 16,
}

REGISTERS = %w{R0 R1 R2 R3 R4 R5 R6 PC}

STRINGS = [
    "Please enter the password: ",
    "Dumping payload...\n",
    "payload.bin"
]

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
    when 'LDR', 'STR', 'MOV_IMM19'
        reg = REGISTERS.index(args[0])
        addr = args[1].to_i
    when 'SHL', 'SHR', 'ADD', 'SUB', 'AND', 'OR', 'XOR', 'CMP'
        reg = REGISTERS.index(args[0])
        addr = REGISTERS.index(args[1]) * 8
    when 'NOT'
        reg = REGISTERS.index(args[0])
    when 'PRINT', 'READLN'
        addr = args[0].to_i
    end
    
    p [ opc | (reg << 8) | (addr << 11) | (cond << 30) ].pack 'V'
    #p [ (opc << 24) | (reg << 21) | (addr << 2) | cond ].pack 'N'
end

def install_rodata(bytecode)
    base = RODATA_BASE_ADDR

    rodata = STRINGS.join('') 
    bytecode[base, rodata.size] = rodata
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

def assemble(prog)
    bytecode = "\x00" * PROGRAM_SIZE
    bytecode[0x38,8] = [ 0x40 ].pack 'Q'

    base = 0x40
    prog.lines.map(&:chomp).each do |line|
        next if line.empty?
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

    install_rodata(bytecode)
    bytecode
end


@bytecode = assemble(<<ASM)
NONE
MOV R0, #{"Please enter the password: ".size}
PRINT #{str_addr("Please enter the password: ")}

READLN #{BSS_BASE_ADDR}
MOV R1, 16
CMP R0, R1

HALT
ASM

@bytecode[0x38,8] = [ 0x40 ].pack 'Q'

File.binwrite(PROGRAM_BIN, @bytecode)
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


