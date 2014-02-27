#!/usr/bin/env ruby

OPCODES = 
{
    'mov.lo' => 1,
    'mov.hi' => 2,
    'xor' => 4,
    'or' => 5,
    'and' => 6,
    'add' => 7,
    'sub' => 8,
    'mul' => 9,
    'div' => 10,
    'jz' => 11,
    'jnz' => 11,
    'js' => 11,
    'jns' => 11,
    'jmp' => 12,
    'ldr' => 13,
    'str' => 14,
}

META = %w{ mov }

REGISTERS = (0..15).to_a.map{|i| "r#{i}"}
CONDITIONS = [ 'z', 'nz', 's', 'ns' ]
LABELS = {}

def encode_hex(prog)
    lines = Array.new((prog.size + 31) / 32) { |n|
        data = prog[n * 32, 32]
        ':%02X%04X00%s%02X' % [ data.size, n * 32, data.unpack('H*')[0].upcase, -data.bytes.inject(0){|a,b| a+b} & 0xff ]
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
        elsif line =~ /^mov / # meta instruction
            base += 4
        else
            base += 2
        end
    end

    LABELS.update(labels)
end

def reg(arg); REGISTERS.index(arg) & 0xf end
def cond(arg); CONDITIONS.index(arg) & 3 end
def addr(label); LABELS[label] end

def encode_insn(pc, opcode, *args)
    fail "Unknown instruction: #{opcode.inspect}"unless OPCODES.include?(opcode) or META.include?(opcode)

    insn = (OPCODES[opcode] << 12) if OPCODES.include?(opcode)
    case opcode
        when 'mov' # meta
            value = LABELS[args[1]] || args[1].hex
            return encode_insn(pc, "mov.hi", args[0], ((value >> 8) & 0xff).to_s(16)) + 
                   encode_insn(pc+2, "mov.lo", args[0], ((value & 0xff).to_s(16)))

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
        when /jmp/
            insn |= (addr(args[0]) - pc) & 1023
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

program = assemble(<<-LISTING)
# SSTIC 2014, remote firmware
xor r0, r0, r0
mov r4, goodbye_str
mov r8, 0xC400

xor r1, r1, r1
mov r2, 1
mov r3, #{"Firmware successfully uploaded.\\n".size}

print_loop:
    sub r15, r3, r1
    jz end
    js end
    ldr r15, r4, r1
    str r15, r8, r0
    add r1, r1, r2
    jmp print_loop

end:
    .data 0,0
    jmp end

goodbye_str:
    .data "Firmware successfully uploaded.\\n"

LISTING

puts encode_hex(program)
File.binwrite('fw.bin', program)
