#!/usr/bin/env ruby

require 'socket'
require 'timeout'
require 'zlib'

EMAIL_SECRET = File.read("email.secret").unpack('C*')
EMAIL_MEM_ADDR = 0xFA00

class Emulator
    class EmulatorException < Exception; end

    module Condition
        Z = 0
        NZ = 1
        S = 2
        NS = 3
    end

    MAX_CLIENT_BY_ADDR = 2
    MAX_LOADING_TIME = 15
    MAX_EXECUTION_TIME = 5
    MAX_FIRMWARE_SIZE = 0x800
    MEMORY_SIZE = 1 << 16
    UNMAPPED_REGION = (0x800 ... 0xC00)
    UART_TX = 0xC400
    EXCEPTION_MESSAGES = 
    {
        bad_insn: "Invalid instruction",
        unaligned_insn: "Unaligned instruction",
        bkpt: "Breakpoint",
        access_violation: "Memory access violation",
        watchdog: "Watchdog timer expired",
        div_by_zero: "Division by zero",
    }
    @@instances = []

    attr_reader :client
    def initialize(client)
        @creation_time = Time.now
        @client = client
        @@instances.push(self)
        STDERR.puts "New client from #{self.remote_ip}" if $DEBUG
    end

    def self.instances
        @@instances
    end

    def self.kill_all(ip = nil)
        @@instances.each {|emu| (ip.nil? or emu.remote_ip == ip) and emu.kill}
    end

    def remote_ip
        @client.peeraddr.last
    end

    def kill(reason = '')
        STDERR.puts "Closing connection with #{self.remote_ip}" if $DEBUG and not @client.closed?
        @client.puts "CLOSING: #{reason}." unless reason.empty? or @client.closed?
        @client.close unless @client.closed?
        @@instances.delete(self)
    end

    def run
        fail("Too many connections.") if @@instances.count {|emu| emu.remote_ip == self.remote_ip } > MAX_CLIENT_BY_ADDR
        load_firmware

        @registers = Array.new(16, 0x0000)
        @pc = 0x0000
        @fault_addr = 0x0000
        @flags = { z:0, s:0 }

        Timeout.timeout(MAX_EXECUTION_TIME) {
            begin
                loop do
                    opcode, args = parse_instruction(@pc)
                    @pc = execute_insn(opcode, args)
                end
            rescue EmulatorException => exc
                crash_report(exc)
                return

            rescue Exception => e
                crash_report(e)
                return
            end
        } rescue exception(:watchdog)
    end

    private

    def exception(type)
        raise EmulatorException, EXCEPTION_MESSAGES[type]
    end

    def memory_read(addr, size)
        if UNMAPPED_REGION.include?(addr) or UNMAPPED_REGION.include?(addr+size) or (addr < UNMAPPED_REGION.begin and addr+size > UNMAPPED_REGION.end)
            @fault_addr = addr
            exception(:access_violation)
        end

        @memory[addr, size]
    end

    def memory_write(addr, value)
        size = value.size
        if UNMAPPED_REGION.include?(addr) or UNMAPPED_REGION.include?(addr+size) or (addr < UNMAPPED_REGION.begin and addr+size > UNMAPPED_REGION.end)
            @fault_addr = addr
            exception(:access_violation)
        elsif addr == UART_TX and value.size == 1
            @client.print(value[0].chr)
            @client.flush
        end

        @memory[addr, size] = value
    end

    def parse_instruction(addr)
        exception(:unaligned_insn) if addr % 2 != 0

        insn = memory_read(addr, 2) 
        args = []
        opcode =
            case insn[0] >> 4
            when 1 then 'mov.lo'
            when 2 then 'mov.hi'
            #when 3 then 'cmp'
            when 4 then 'xor'
            when 5 then 'or'
            when 6 then 'and'
            when 7 then 'add'
            when 8 then 'sub'
            when 9 then 'mul'
            when 10 then 'div'
            when 11 then 'jcc'
            when 12 then 'jmp'
            when 13 then 'ldr'
            when 14 then 'str'
            when 15 then exception(:bkpt)
                else exception(:bad_insn)
            end

        case opcode
        when 'mov.lo', 'mov.hi'
            args.push(insn[0] & 0xf) # destination register
            args.push(insn[1])       # 8 bit immediate

        #when 'cmp'
        #    args.push(insn[1] >> 4)  # source register 1
        #    args.push(insn[1] & 0xf) # source register 2

        when 'xor', 'or', 'and', 'add', 'sub', 'mul', 'div'
            args.push(insn[0] & 0xf)  # destination register
            args.push(insn[1] >> 4)   # source register 1
            args.push(insn[1] & 0xf)  # source register 2

        when 'jcc'
            args.push((insn[0] >> 2) & 3)              # condition: 2 bits
            args.push(((insn[0] & 3) << 8) | insn[1]) # destination offset: 10 bits
            if args.last[9] == 1
                args[-1] |= 0xfc00 # sign extend
            end

        when 'jmp'
            args.push(((insn[0] & 3) << 8) | insn[1]) # destination offset: 10 bits
            if args.last[9] == 1
                args[-1] |= 0xfc00 # sign extend
            end

        when 'ldr', 'str'
            args.push(insn[0] & 0xf) # register
            args.push(insn[1] >> 4)  # register base
            args.push(insn[1] & 0xf) # register offset
        end

        [ opcode, args ]
    end

    def check_condition(cond)
        case cond
        when Condition::Z then (@flags[:z] != 0)
        when Condition::NZ then (@flags[:z] == 0)
        when Condition::S then (@flags[:s] != 0)
        when Condition::NS then (@flags[:s] == 0)
        end
    end

    def execute_insn(opcode, args)
        STDERR.puts "Executing #{opcode} #{args.join(', ')}" if $DEBUG
        case opcode
            when 'jmp'
                return (@pc + args[0]) & 0xffff
            when 'jcc'
                return (check_condition(args[0]) ? (@pc + args[1]) : (@pc + 2)) & 0xffff

            when 'mov.lo'
                @registers[args[0]] &= 0xff00
                @registers[args[0]] |= args[1]
                update_flags(@registers[args[0]])
            when 'mov.hi'
                @registers[args[0]] &= 0x00ff
                @registers[args[0]] |= (args[1] << 8)
                update_flags(@registers[args[0]])
            when 'xor'
                @registers[args[0]] = (@registers[args[1]] ^ @registers[args[2]]) & 0xffff
                update_flags(@registers[args[0]])
            when 'or'
                @registers[args[0]] = (@registers[args[1]] | @registers[args[2]]) & 0xffff
                update_flags(@registers[args[0]])
            when 'and'
                @registers[args[0]] = (@registers[args[1]] & @registers[args[2]]) & 0xffff
                update_flags(@registers[args[0]])
            when 'add'
                @registers[args[0]] = (@registers[args[1]] + @registers[args[2]]) & 0xffff
                update_flags(@registers[args[0]])
            when 'sub'
                @registers[args[0]] = (@registers[args[1]] - @registers[args[2]]) & 0xffff
                update_flags(@registers[args[0]])
            when 'mul'
                @registers[args[0]] = (@registers[args[1]] * @registers[args[2]]) & 0xffff
                update_flags(@registers[args[0]])
            when 'div'
                exception(:div_by_zero) if @registers[args[2]].zero?
                @registers[args[0]] = (@registers[args[1]] / @registers[args[2]]) & 0xffff
                update_flags(@registers[args[0]])

            when 'ldr'
                byte = memory_read(@registers[args[1]] + @registers[args[2]], 1)[0]
                @registers[args[0]] &= 0xff00
                @registers[args[0]] |= byte
            when 'str'
                byte = @registers[args[0]] & 0x00ff
                memory_write(@registers[args[1]] + @registers[args[2]], [ byte ])

            when 'bkpt'
                exception(:bkpt)
        end

        (@pc + 2) & 0xffff
    end

    def update_flags(result)
        @flags[:z] = (result != 0x0000) ? 0 : 1
        @flags[:s] = (result & 0x8000 == 0) ? 0 : 1
    end

    def load_firmware
        Timeout.timeout(MAX_LOADING_TIME) do
            fw_size = @client.read(2)
            fail("invalid packet size") if fw_size.length != 2

            crc = @client.read(4)
            fail("invalid checksum") if crc.length != 4
            
            fw_size = fw_size.unpack('n')[0]
            fail("invalid firmware size") if fw_size.zero? or fw_size > MAX_FIRMWARE_SIZE

            fw_data = @client.read(fw_size)
            fail("not enough data") if fw_data.length != fw_size

            fail("checksum verification failed") if Zlib.crc32(fw_data) != crc.unpack('N')[0]

            @memory = Array.new(MEMORY_SIZE, 0)
            @memory[EMAIL_MEM_ADDR, EMAIL_SECRET.size] = EMAIL_SECRET
            @memory[0, fw_size] = fw_data.unpack('C*')
        end
    end

    def crash_report(exception)
        @client.puts("-- Exception occurred at %04X: #{exception.message}." % @pc)
        dump_registers 
    end
    
    def dump_registers
    begin
        @client.puts <<-REGS
   r0:#{"%04X" % @registers[0]}     r1:#{"%04X" % @registers[1]}    r2:#{"%04X" % @registers[2]}    r3:#{"%04X" % @registers[3]}
   r4:#{"%04X" % @registers[4]}     r5:#{"%04X" % @registers[5]}    r6:#{"%04X" % @registers[6]}    r7:#{"%04X" % @registers[7]}
   r8:#{"%04X" % @registers[8]}     r9:#{"%04X" % @registers[9]}   r10:#{"%04X" % @registers[10]}   r11:#{"%04X" % @registers[11]}
  r12:#{"%04X" % @registers[12]}    r13:#{"%04X" % @registers[13]}   r14:#{"%04X" % @registers[14]}   r15:#{"%04X" % @registers[15]}
   pc:#{"%04X" % @pc} fault_addr:#{"%04X" % @fault_addr} [S:#{@flags[:s]} Z:#{@flags[:z]}]
        REGS
    rescue Exception => e
        p e.message
    end
    end
end

server = TCPServer.new 20000
loop do
    Thread.start(server.accept) do |client|
        emu = Emulator.new(client)
        begin
            emu.run

        rescue Exception => exc
            emu.kill(exc.message)
        ensure
            emu.kill
        end
    end
end

__END__
