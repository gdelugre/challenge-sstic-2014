class CPU::AArch64
    EXPAND_PATTERNS =
    {
        InstructionPattern.new("mov ${Xx}, 0") =>
            [
                -> (map) {
                    zero_reg = map['Xx'][0] == ?w ? 'wzr' : 'xzr'
                    rand_cond = self.condition_codes.sample
                    opc = %w{csel csneg}.sample
                    if rand_cond == 'al'
                        InstructionPattern.new("#{opc} ${Xx}, #{zero_reg} , ${Xx}, al").make(map)
                    else
                        InstructionPattern.new(<<-CSEL).make(map)
                            #{opc} ${Xx}, #{zero_reg}, ${Xx}, #{rand_cond}
                            #{opc} ${Xx}, #{zero_reg}, ${Xx}, #{self.negate_condition(rand_cond)}
                        CSEL
                    end
                }
            ],

        #InstructionPattern.new("add ${Xx}, ${Xx}, 1") => InstructionPattern.new("cinc ${Xx}, ${Xx}, al"),

        InstructionPattern.new("mov ${Rx}, ${Ry}") =>
            [
                InstructionPattern.new(<<-CODE),
                    mvn ${Rx}, ${Ry}
                    mvn ${Rx}, ${Rx}
                CODE

                InstructionPattern.new(<<-CODE),
                    eor ${Rx}, ${Rx}, ${Ry}
                    eor ${Ry}, ${Ry}, ${Rx}
                    eor ${Rx}, ${Ry}, ${Rx}
                    mov ${Ry}, ${Rx}
                CODE

                InstructionPattern.new("and ${Rx}, ${Ry}, ${Ry}"),
                InstructionPattern.new("orr ${Rx}, ${Ry}, ${Ry}"),
            ],

        InstructionPattern.new("mov ${Rx}, ${Im}") =>
            [
                -> (map) {
                    imm = map['Im'].to_i & 0xffff_ffff_ffff_ffff
                    if (0..58).include?(imm)
                        return InstructionPattern.new(self.zero_register(map['Rx']).to_s + "\n" + "add ${Rx}, ${Rx}, 1\n" * imm).make(map) if (0..8).include?(imm) and rand(2) == 1
                        return InstructionPattern.new(<<-CLZ).make(map)
                            mov ${Rx}, #{(rand(0..63) | 32) << (58 - imm)}
                            clz ${Rx}, ${Rx}
                        CLZ
                    end
                    return nil if imm.to_s(2).count('1') > 6

                    # Immediation move must be imm16
                    fake_imm = 0x10000
                    while fake_imm > 0xffff
                        shift = rand(0..63)
                        fake_imm = self.ror64(imm, shift)
                        #p "imm = #{imm}", "fake_imm = #{fake_imm}"
                    end

                    #p "shift = #{shift}"
                    #p "fake_imm = #{fake_imm.to_s(16)}"

                    InstructionPattern.new(<<-FAKEIMM + <<-ADJUST).make(map)
                        mov ${Rx}, #{fake_imm}
                    FAKEIMM
                        ror ${Rx}, ${Rx}, #{(64 - shift) % 64}
                    ADJUST
                },
            ],

        InstructionPattern.new("add ${Rx}, ${Rx}, ${Xi}") =>
            [
                -> (map) {
                    if map['Xi'] =~ /^:lo12:[^.]/
                        rand_shift = rand(1 .. 12) * 4
                        if rand_shift > 0
                            InstructionPattern.new(<<-SUB).make(map)
                                add ${Rx}, ${Rx}, ${Xi}+#{rand_shift}
                                sub ${Rx}, ${Rx}, #{rand_shift}
                            SUB
                        else
                            InstructionPattern.new(<<-ADD).make(map)
                                add ${Rx}, ${Rx}, ${Xi}-#{-rand_shift}
                                add ${Rx}, ${Rx}, #{-rand_shift}
                            ADD
                        end
                    elsif self.is_immediate?(map['Xi'])
                        rand_value = rand(0 .. (4095 - map['Xi'].to_i))

                        InstructionPattern.new(<<-SUB).make(map)
                            sub ${Rx}, ${Rx}, #{rand_value}
                            add ${Rx}, ${Rx}, #{map['Xi'].to_i + rand_value}
                        SUB
                    else
                        return nil
                    end
                }
            ],

       InstructionPattern.new("str ${Xx}, [${Xb},${Xi}]") =>
            -> (map) {
                return nil unless self.is_immediate?(map['Xi']) or map['Xi'][0] == ?-
                offset = map['Xi'].to_i
                rand_shift = rand(0..(offset / 8)) * 8
                InstructionPattern.new(<<-STR).make(map)
                    add ${Xb}, ${Xb}, #{offset - rand_shift}    
                    str ${Xx}, [${Xb},#{rand_shift}]
                    sub ${Xb}, ${Xb}, #{offset - rand_shift}
                STR
            },

       InstructionPattern.new("ret") => InstructionPattern.new("br x30"),
       #InstructionPattern.new("br ${Rx}") => InstructionPattern.new("ret ${Rx}"),
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
# Replace code using instruction patterns.
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
                        puts insn if $DEBUG
                        replace = expand_insn(transform, map)
                        p replace if $DEBUG
                        break
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

