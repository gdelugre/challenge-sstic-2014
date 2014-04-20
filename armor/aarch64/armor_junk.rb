class CPU::AArch64
    NOOP =
    [
        InstructionPattern.new('nop'),
        InstructionPattern.new('hint #0'),
        InstructionPattern.new('mov ${Rx}, ${Rx}'),
        InstructionPattern.new('add ${Rx}, ${Rx}, #0'),
        InstructionPattern.new('add ${Rx}, ${Rx}, xzr'),
        InstructionPattern.new('sub ${Rx}, ${Rx}, #0'),
        InstructionPattern.new('sub ${Rx}, ${Rx}, xzr'),
        InstructionPattern.new('orr ${Rx}, ${Rx}, ${Rx}'),
        InstructionPattern.new('orr ${Rx}, ${Rx}, xzr'),
        InstructionPattern.new('eor ${Rx}, ${Rx}, xzr'),
        InstructionPattern.new('and ${Rx}, ${Rx}, ${Rx}'),
        InstructionPattern.new('bic ${Rx}, ${Rx}, xzr'),
        InstructionPattern.new('madd ${Rx}, ${R}, xzr, ${Rx}'),
        InstructionPattern.new('csel ${Rx}, ${Rx}, ${R}, al'),
    ]
end

#
# Inserts dummy instructions at random positions.
#
class InsertJunk < ArmorPass
    NAME = 'junk'

    def apply(assembly)
        assembly.each_block {|blk|
            blk.each_instruction {|insn|
                [CPU::AArch64::NOOP.sample.make, insn].flatten if rand(20).zero?
            }
        }
    end
end

