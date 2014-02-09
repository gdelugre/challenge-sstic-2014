#
# Shuffles instructions into each basic block.
#
class ShuffleCode < ArmorPass
    NAME = "shuffle_insns"

    def apply(assembly)
        assembly.each_block { |blk|
            next if blk.empty?
            next if blk.instructions.all?{|insn| insn.is_branch?}

            reg_usage = assembly.cpu.analyze_registers(blk)

            shifts = Array.new(blk.size)

            # For each register usage on each instruction
            reg_usage.shift
            reg_usage.pop if blk.instructions[-1].is_branch?

            reg_usage.each_with_index { |regs,i|

                max_pos = [ reg_usage.size-1, reg_usage.size-1 ]

                # If a register is read, find the nearest write to it
                regs[:read].each { |r|
                    x = i + 1 + (reg_usage[i+1..-1].find_index{|future| future[:write].include?(r)} || -1)
                    max_pos[0] = x - 1 unless x == i or x - 1 >= max_pos[0]
                }

                # If a register is written, find the nearest read on it
                regs[:write].each { |r|
                    x = i + 1 + (reg_usage[i+1..-1].find_index{|future| future[:read].include?(r)} || -1)
                    max_pos[1] = x - 1 unless x == i or x - 1 >= max_pos[1]
                }

                shifts[i] = max_pos.min
            }
            #require 'pp'
            #pp reg_usage
            #pp shifts
            #puts blk.to_s

            # Generates a new shuffled block.
            shuffled = []
            (blk.size - 1).downto(0) do |i|
                max_pos = shifts[i]
                if not max_pos or max_pos == i # no shuffle possible
                    shuffled[i] = blk.instructions[i]
                else
                    shuffled.insert(rand(i..max_pos), blk.instructions[i])
                end
            end

            # Replace instructions in the original block.
            i = -1
            shuffled.compact!
            blk.each_instruction do |insn|
                i += 1
                shuffled[i]
            end
        }
    end
end

