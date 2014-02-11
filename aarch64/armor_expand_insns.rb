class CPU::AArch64
    EXPAND_PATTERNS =
    {
        InstructionPattern.new("mov ${Rx}, ${Ry}") =>
            [
                InstructionPattern.new(<<-CODE)
                    mvn ${Rx}, ${Ry}
                    mvn ${Rx}, ${Rx}
                 CODE
            ],

        InstructionPattern.new("mov ${Rx}, ${Im}") =>
            [
                -> (map) {
                    imm = map['Im'].to_i & 0xffff_ffff_ffff_ffff
                    return InstructionPattern.new(self.zero_register(map['Rx']).to_s + "\n" + "add ${Rx}, ${Rx}, 1\n" * imm).make(map) if (0..8).include?(imm)
                    return nil if imm.to_s(2).count('1') > 6

                    # Immediation move must be imm16
                    fake_imm = 0x10000
                    while fake_imm > 0xffff
                        shift = rand(0..63)
                        fake_imm = self.ror64(imm, shift)
                        p "imm = #{imm}", "fake_imm = #{fake_imm}"
                    end

                    p "shift = #{shift}"
                    p "fake_imm = #{fake_imm.to_s(16)}"

                    InstructionPattern.new(<<-FAKEIMM + <<-ADJUST.lines.shuffle.join($/)).make(map)
                        mov ${Rx}, #{fake_imm}
                    FAKEIMM
                        ror ${Rx}, ${Rx}, #{(64 - shift) % 64}
                    ADJUST
                },
            ]
    }

    def self.zero_register(reg)
        [
            Instruction.new('mul', reg, reg, 'xzr'),
            Instruction.new('eor', reg, reg, reg),
            Instruction.new('and', reg, reg, 'xzr'),
            Instruction.new('sub', reg, reg, reg),
        ].sample
    end

    def self.rand_imm64
        s = ("1" * rand(1..64)).to_i(2)
        r = rand(0..63)

        self.ror64(s, r)
    end

    def self.rol64(x, shift)
        ((x >> (64 - shift)) | (x << shift)) & 0xffff_ffff_ffff_ffff
    end

    def self.ror64(x, shift)
        ((x >> shift) | (x << (64 - shift))) & 0xffff_ffff_ffff_ffff
    end
end

#
# 
#
class ExpandCode < ArmorPass
    NAME = 'expand_insns'

    def apply(assembly)
        assembly.each_block {|blk|
            blk.each_instruction {|insn|
                replace = nil
                assembly.cpu::EXPAND_PATTERNS.each_pair do |pattern, transform|
                    if match = pattern.match(insn)
                        map = match_to_hash(match)
                        puts insn
                        replace = expand_insn(transform, map)
                        p replace
                    end
                end if rand(2).zero?
                
                replace
            }
        }
    end

    private

    def expand_insn(transform, map)
        case transform
        when CPU::InstructionPattern then transform.make(map)
        when Array then expand_insn(transform.sample, map)
        when Proc then transform.call(map)
        end
    end
    
    # Converts MatchData object to an Hash.
    def match_to_hash(match)
        match.names.map {|name| [name, match[name]]}.to_h
    end
end

