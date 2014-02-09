#!/usr/bin/env ruby

require 'optparse'

class OptParser
    BANNER = <<-USAGE
Usage: #{$0} <assembly-file> -e <pass> [-o output]
    USAGE

    def self.parser(options)
        OptionParser.new do |opts|
            opts.banner = BANNER
            opts.on("-o <output>", "Output to file.") do |o|
                options[:output] = o
            end

            opts.on("-e", "--enable <pass1,pass2,...>", "Choose armoring pass to enable.") do |p|
                options[:passes] += p.split(',')
            end

            opts.on_tail("-h", "Show this message") do
                puts opts
                exit
            end
        end
    end

    def self.parse(args)
        options = 
        {
            :passes => []
        }
        self.parser(options).parse!(args)
        options
    end
end

class CPU
    class Instruction
        attr_reader :opcode, :operands
        def initialize(opcode, *operands)
            @opcode = opcode
            @operands = operands
        end

        def =~(pattern)
            case pattern
            when Regexp then self.to_s =~ pattern
            else self.to_s =~ pattern.to_re
            end
        end

        def to_s
            "\t#{@opcode} #{@operands.join(", ")}"
        end
    end

    class InstructionPattern
        def initialize(pattern)
            @pattern = pattern
        end

        def make
            regs = {}
            insn = @pattern.gsub(/\${[R](\w?)}/) { |token|
                if $1.empty?
                    @cpu.general_registers.sample
                else
                    regs[$1] ||= @cpu.general_registers.sample
                end
            }
            "\t#{insn}" 
        end

        def to_re
            %r{^\t#{
                backrefs = []
                @pattern
                    .gsub(/\s+/,"\\s+")                 # expand white characters
                    .gsub(/\${([R])(\w?)}/) { |token|   # expand tokens
                        if $2.empty?
                            "(#{@cpu.general_registers.join('|')})"
                        elsif backrefs.include?($2)
                            "(\\k<#{$1}#{$2}>)"
                        else
                            backrefs.push($2)
                            "(?<#{$1}#{$2}>#{@cpu.general_registers.join('|')})"
                        end
                    }
            }}
        end

        def ===(insn)
            not (insn.to_s =~ self.to_re).nil?
        end
    end
end

class Function
    attr_reader :name, :entry
    def initialize(name, entry) 
        @name, @entry = name, entry
    end

    def each_block(&b)
        browsed = [] 
        children = [ @entry ]

        until children.empty?
            block = children.pop
            b.call(block)
            children += block.children.select{|blk| not browsed.include?(blk) }
        end
    end
end

class Block
    attr_accessor :label, :from, :to
    attr_accessor :dirty
    attr_reader :instructions
    def initialize(assembly, label, from, to, *insns)
        @assembly = assembly
        @label = label
        @from, @to = from, to
        @instructions = insns
        @dirty = false
    end

    def each_instruction(&process)
        i = 0
        while i < @instructions.size
            if insert = process.call(@instructions[i])
                insert = [ insert ] unless insert.kind_of?(Array)
                @instructions[i,1] = insert
                i += insert.size - 1
                self.dirty!
            end
            
            i += 1
        end
    end

    def children
        blocks = [] 
        last_insn = @instructions.last
        if last_insn.is_branch?
            blocks.push @assembly.block(last_insn.destination)
            blocks.push @assembly.block(@to + 1) unless last_insn.is_unconditional_branch?
        else
            blocks.push @assembly.block(@to + 1)
        end
        blocks.compact
    end

    def empty?; self.size.zero? end
    def dirty?; @dirty end
    def dirty!; @dirty = true end
    def size; @instructions.size end
    def [](i); @instructions[i] end

    def to_s
        @instructions.join($/)
    end
end

class AssemblyFileParser
    attr_reader :cpu, :labels
    def initialize(cpu, path)
        @cpu = cpu
        @lines = File.read(path).lines.to_a.compact.map(&:chomp)

        reparse
    end

    def dump
        @lines.join($/) + $/
    end

    def add_label(pos, name, *insns); add_lines(pos, ["#{name}:"] + insns.map{|insn| "\t#{insn}"}); end
    def add_instructions(pos, *insns); add_lines(pos, *insns.map{|insn| "\t#{insn}"}) end

    def flush!
        @blocks.select {|blk| blk.dirty? }.sort_by {|blk| -blk.from }.each do |blk|
            block_lines = []
            block_lines.push("#{blk.label}:") if blk.label 
            block_lines += blk.instructions.map(&:to_s)
            @lines[blk.from .. blk.to] = block_lines
            blk.dirty = false
        end

        reparse
    end

    def blocks
        @blocks.map{|blk| Block.new(self, blk.label, blk.from, blk.to, *blk.instructions.dup)}
    end

    def each_block(&b)
        @blocks.each(&b)
        flush!
    end

    def each_function(&b)
        @functions.each(&b)
        flush!
    end

    def block(where)
        case where
        when Integer then @blocks.find{|blk| (blk.from..blk.to).include?(where)}
        when String
           @blocks.find{|blk| blk.from == @labels[where]} if @labels.include?(where)
        end
    end

    def function(name)
        @functions.find{|fun| fun.name == name}
    end

    def generate_label
        label = ".L1000"
        label.next! while @labels.include?(label)
        @labels[label] = nil

        label
    end

    private
    def reparse
        line_number = 0
        block_from = nil
        current_label = nil
        insns = []
        @blocks = []
        @labels = {}
        @lines.each do |line|
            if line =~ /^([^\t]+):$/
                @labels[$1] = line_number
                if block_from
                    @blocks.push Block.new(self, current_label, block_from, line_number - 1, *insns) unless insns.empty?
                    insns = []
                end
                block_from = line_number
                current_label = $1

            elsif line.length > 1 and line[0] == ?\t and line[1] != ?.
                insns.push(insn = @cpu.parse_instruction(line))
                block_from ||= line_number
                if insn.is_branch?
                    @blocks.push Block.new(self, current_label, block_from, line_number, *insns)
                    block_from = nil
                    current_label = nil
                    insns = []
                end
            end
            line_number += 1
        end

        @functions = @labels.map {|label,line| 
            if label[0] != "." and entry = self.block(line)
                Function.new(label, entry)
            end
        }.compact!
    end

    def add_lines(pos, *lines)
        @lines.insert(pos, *lines)
        reparse
    end
end

class ArmorPass
    @defined = []

    attr_reader :name
    def name
        self.class::NAME
    end

    def self.inherited(base)
        @defined.push(base.new)
    end

    def self.each_defined(&b); @defined.each(&b) end

    def apply(_assembly)
        raise NotImplementedError
    end
end

$: << "."
require 'aarch64/cpu'
Dir["aarch64/armor_*.rb"].each {|mod| require mod}

@options = OptParser.parse(ARGV)
if ARGV.empty?
    STDERR.puts "No assembly file given."
    exit 1
end

if @options[:passes].empty?
    STDERR.puts "Warning: no pass enabled."
end

assembly = AssemblyFileParser.new(CPU::AArch64, ARGV[0])

ArmorPass.each_defined do |pass|
    if @options[:passes].include?(pass.name)
        puts "[+] Applying pass '#{pass.name}' on #{ARGV[0]}..."
        pass.apply(assembly) 
        assembly.flush!
    end
end

#p CPU::AArch64::NOOP.last.to_re
#p "\tmadd x25, x3, xzr, x25" =~ CPU::AArch64::NOOP.last.to_re
#p $1, $2, $3, $4
#p $~[:Rx]

File.open(@options[:output] || ARGV[0], 'wb') do |fd|
    fd.write(assembly.dump)
end

