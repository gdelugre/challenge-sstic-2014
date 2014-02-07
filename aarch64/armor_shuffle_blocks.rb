class CPU::AArch64
    def self.inconditional_branch_to(label)
        Instruction.new("b", label)
    end
end

#
# Shuffle blocks inside an assembly file.
# Interlaces functions as a result.
#
class ShuffleBlocks < ArmorPass
    NAME = 'shuffle_blocks'

    def apply(assembly)

        srand(2)
        # Generates a new randomized layout.
        # XXX: Shuffling adjacent blocks can cause problems.
        flip = true
        layout = assembly.blocks.select{|blk| flip = not(flip); flip and blk.label and blk.label[0] == "."}.shuffle!

        i = 0
        assembly.each_block { |blk|
            if layout.any?{|sblk| sblk.from == blk.from}

                # Replace label and instructions into current block
                blk.label = layout[i].label
                blk.instructions.replace(layout[i].instructions)

                # Glue to next original block
                if next_block = assembly.block(layout[i].to + 1) 
                    dummy_label = next_block.label || assembly.generate_label
                    if next_block.label.nil?
                        next_block.label = dummy_label
                        next_block.dirty!
                    end

                    blk.instructions.push assembly.cpu.inconditional_branch_to(dummy_label)
                end

                # Glue to previous original block
                if prev_block = assembly.block(layout[i].from - 1)
                    prev_block.instructions.push assembly.cpu.inconditional_branch_to(blk.label)
                    prev_block.dirty!
                end

                blk.dirty!
                i += 1
            end
        }
    end 
end

