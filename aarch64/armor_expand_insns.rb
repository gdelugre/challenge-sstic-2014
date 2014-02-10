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
                    imm = map[:Im].to_i
                    imm_size = imm.to_s(2).size
                    rand_imm = rand(1..(1<<imm_size))

                    InstructionPattern.new(<<-CODE).make(map)
                        mov ${Rx}, ~(${Im} ^ #{rand_imm})
                        eor ${Rx}, ${Rx}, #{rand_imm}
                        mvn ${Rx}, ${Rx}
                    CODE
                },
            ]
    }
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
                        replace = expand_insn(transform, map)
                    end
                end if rand(4).zero?
                
                replace
            }
        }
    end

    private

    def expand_insn(transform, map)
        case transform
        when CPU::InstructionPattern then transform.make(map)
        when Array then expand_insn(transform.sample, map)
        when Proc then transform[map]
        end
    end
    
    # Converts MatchData object to an Hash.
    def match_to_hash(match)
        match.names.map {|name| [name, match[name]]}.to_h
    end
end

