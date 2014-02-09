class CPU::AArch64 < CPU
    GENERAL_REGISTERS = 
    {
        64 => (0..30).to_a.map{|i| "x#{i}"},
        32 => (0..30).to_a.map{|i| "w#{i}"}
    }

    REGISTERS = 
    {
        64 => GENERAL_REGISTERS[64] + ['sp', 'cpsr'],
        32 => GENERAL_REGISTERS[32]
    }

    class Vector
        attr_reader :base, :repr
        def initialize(base, repr) 
            @base, @repr = base, repr
        end

        def to_s
            "{#{@base}.#{@repr}}"
        end
    end

    class Pointer
        attr_reader :base, :offset, :preinc
        def initialize(base, offset = 0, preinc = false)
            @base, @offset = base, offset
            @preinc = preinc
        end

        def to_s
            str = ""
            if @offset == "0"
                str += "[#{@base}]"
            else
                str += "[#{@base},#{@offset}]"
            end
            str += "!" if @preinc
            str
        end

        def self.[](base, offset = 0, preinc = false)
            self.new(base, offset, preinc)
        end
    end

    class Instruction < CPU::Instruction
        def is_branch?
            case @opcode
            when /^b/, 'ret', /^[tc]b/ then true
            else false
            end
        end
        
        def is_unconditional_branch?
            %w{b bl br blr ret}.include?(@opcode)
        end

        def destination
            fail "Not a branch instruction" unless is_branch?

            case @opcode
            when /^b/ then @operands.first
            when 'ret' then @operands.empty? ? 'r30' : @operands.first
            when /^cb/ then @operands[1]
            when /^tb/ then @operands[2]
            end
        end

        def modified_registers
            modified = []
            modified.push('cpsr') if @opcode[-1,1] == 's' and @opcode != 'sys'

            case @opcode
            when 'svc', 'sys'
                modified += REGISTERS[64].dup
            when /c?cm[pn]/, 'tst'
                modified.push 'cpsr'
            when /^st.*/
                start = (@opcode =~ /^stx?p/) ? 2 : 1
                if @operands[start].is_a?(Pointer) and (@operands[start].preinc or @operands.size > start+1)
                    modified.push @operands[start].base
                end
            when /^ld.*/
                start = (@opcode =~ /^ldx?p/) ? 2 : 1
                modified += @operands[0,start]
                if @operands[start].is_a?(Pointer) and (@operands[start].preinc or @operands.size > start+1)
                    modified.push @operands[start].base
                end
            else
                modified.push @operands.first if @operands.size > 1
            end

            modified.map! {|opnd| CPU::AArch64.super_register(opnd) if CPU::AArch64.is_register?(opnd) }.compact
        end

        def accessed_registers
            used = []

            case @opcode
            when 'svc', 'sys'
                return REGISTERS[64].dup
            when /c?cm[p|n]/, /cin[cv]/, 'cneg', 'tst', /^cb.*/, /^cs.*/, /^tb.*/
                used.push 'cpsr'
                start = 0
            when /^st.*/
                start = 0
            when /^ldx?p/
                start = 2
            else
                start = 1
            end

            @operands[start..-1].each {|opnd|
                case opnd
                when Vector then used.push(opnd.base)
                when Pointer
                    used.push(opnd.base)
                    used.push(opnd.offset)
                else
                    used.push(opnd)
                end
            } if @operands.size > 1

            used.map! {|opnd| CPU::AArch64.super_register(opnd) if CPU::AArch64.is_register?(opnd) }.compact
        end
    end

    def self.parse_instruction(line)
        if line =~ /^\t(\w+)$/
            return Instruction.new($1)
        elsif line =~ /^\t(\w+)\s(.*)$/
            opcode = $1
            operands = $2.gsub(/\[[^\[\]]*\]/) {|ptr| ptr.gsub(", ",",")} # normalize in splitable format
            return Instruction.new(opcode, *operands.split(/, /).map{|opnd| self.parse_operand(opnd)})
        else
            fail "Bad instruction : #{line}"
        end
    end

    def self.parse_operand(operand)
        case operand
        when /\[(\w+)\](!?)/ then Pointer[$1, '0', (not $2.empty?)]
        when /\[([^,]+),([^,]+)\](!?)/ then Pointer[$1, $2, (not $3.empty?)]
        when /{(\w+)\.(\w+)}/ then Vector.new($1, $2)
        else operand
        end
    end

    def self.is_register?(name)
        REGISTERS.values.any? {|regset| regset.include?(name) }
    end

    def self.general_registers
        GENERAL_REGISTERS[64]
    end

    class InstructionPattern < CPU::InstructionPattern
        def initialize(pattern)
            super(pattern)
            @cpu = CPU::AArch64
        end
    end

    def self.super_register(reg)
        case reg
        when /w(\d+)/ then "x#{$1}"
        else reg
        end
    end

    def self.analyze_registers(block)
        current = { :read => REGISTERS[64].dup, :write => REGISTERS[64].dup }
        states = [ current ]

        block.each_instruction do |insn|
            wr = insn.modified_registers
            rr = insn.accessed_registers
            states.push(:read => rr, :write => wr)

            nil # do not modify block
        end

        states
    end

    def self.allocatable_registers(usage)
       trashable = []
       REGISTERS[64].each { |reg|
            usage.each {|state|
                break if state[:read].include?(reg)
                if state[:write].include?(reg)
                    trashable.push(reg)
                    break
                end
            }
       } 

       trashable
    end
end

