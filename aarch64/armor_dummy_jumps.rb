class CPU::AArch64
end

#
# Inserts dummy jumps at random positions.
#
class InsertDummyJumps < ArmorPass
    NAME = 'insert_dummy_jumps'

    def apply(assembly)
        assembly.each_block {|blk|
            #
            # If the block ends with a branch to label.
            #
            if blk.instructions.last.opcode == 'b'
                reg_usage = assembly.cpu.analyze_registers(blk)
                reg_usage.pop

                known_values = {}
                i = 0
                blk.each_instruction { |insn|
                    i += 1
                    if match = CPU::AArch64::InstructionPattern.new("mov ${Rx}, ${Im}").match(insn)
                        imm = match['Im'].to_i
                        if not reg_usage[i+1..-1].find{|set| set[:write].include?(match['Rx'])}
                            known_values[match['Rx']] = imm
                        end
                        nil
                    #
                    # We know some constant register values at branching time.
                    # 
                    elsif insn.opcode == 'b' and known_values.size > 0
                        real_dest = insn.operands[0]
                        labels = assembly.labels.sort_by{|label, line| line}

                        #p real_dest
                        #p known_values
                        link = %i{or}.sample
                        real_dest_reached = false
                        cmps = []
                        if link == :or
                            known_values.each { |reg, val|
                                cmps.push CPU::AArch64::Instruction.new("cmp", reg, "0")
                                if rand(2).zero?
                                    cmps.push CPU::AArch64::Instruction.new("b#{val.zero? ? 'eq' : 'ne'}", real_dest)
                                    real_dest_reached |= true
                                else
                                    fake_dest = generate_fake_destination(labels, real_dest)
                                    cmps.push CPU::AArch64::Instruction.new("b#{val.zero? ? 'ne' : 'eq'}", fake_dest)
                                end
                            }
                        elsif link == :and
                            #TODO
                        end

                        final_dest = real_dest_reached ? generate_fake_destination(labels, real_dest) : real_dest
                        cmps.push CPU::AArch64::Instruction.new("b", final_dest)
 
                        cmps
                    else
                        nil
                    end
                }
            end
        }
    end

    private

    def generate_fake_destination(labels, near)
        near_index = labels.index {|label,line| label == near}
        if near_index.nil?
            near
        else
            fake_index = near_index + rand(-3..3)
            labels[fake_index][0]
        end
    end
end

