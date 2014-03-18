class CPU::AArch64
end

#
# Inserts dummy jumps at random positions.
#
class InsertDummyJumps < ArmorPass
    NAME = 'insert_dummy_jumps'

    def apply(assembly)
        assembly.each_block {|blk|
            blk.each_instruction {|insn|
                nil
                # TODO
            }
        }
    end
end

