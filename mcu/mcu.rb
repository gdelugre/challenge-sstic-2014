#!/usr/bin/env ruby

require 'etc'
require 'socket'
require 'timeout'
require 'zlib'
require 'openssl'

RUN_AS_USER = 'mcu'
SERVER_POOL_NPROCESS = 8
EMAIL_SECRET = "fufufufufu@challenge.sstic.org"

class Emulator
    class EmulatorException < Exception; end

    module Condition
        Z = 0
        NZ = 1
        S = 2
        NS = 3
    end

    ROM = File.binread('rom.bin').bytes
    ROM_REGION = (0xFD00 .. 0xFFFF)
    RC4_SECRET_KEY = "YeahRiscIsGood!"

    PROTECTED_MEMORY_REGION = (0xF000 .. 0xFBFF)
 #<<-PROTECTED.rjust(PROTECTED_MEMORY_REGION.size, "\x00").unpack('C*')
    PROTECTED_MEMORY = <<-PROTECTED.unpack('C*').pack('C*').rjust(PROTECTED_MEMORY_REGION.size, "\x00").bytes
        ▄              ▄
        ▌▒█           ▄▀▒▌
        ▌▒▒▀▄       ▄▀▒▒▒▐
       ▐▄▀▒▒▀▀▀▀▄▄▄▀▒▒▒▒▒▐
─────▄▄▀▒▒▒▒▒▒▒▒▒▒▒█▒▒▄█▒▐
───▄▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▀██▀▒▌  WOW
──▐▒▒▒▄▄▄▒▒▒▒▒▒▒▒▒▒▒▒▒▀▄▒▒▌
──▌▒▒▐▄█▀▒▒▒▒▄▀█▄▒▒▒▒▒▒▒█▒▐   SUCH EXPLOIT
─▐▒▒▒▒▒▒▒▒▒▒▒▌██▀▒▒▒▒▒▒▒▒▀▄▌
─▌▒▀▄██▄▒▒▒▒▒▒▒▒▒▒▒░░░░▒▒▒▒▌    VERY CHALLENGING
─▌▀▐▄█▄█▌▄▒▀▒▒▒▒▒▒░░░░░░▒▒▒▐
▐▒▀▐▀▐▀▒▒▄▄▒▄▒▒▒▒▒░░░░░░▒▒▒▒▌   MUCH WIN
▐▒▒▒▀▀▄▄▒▒▒▄▒▒▒▒▒▒░░░░░░▒▒▒▐
─▌▒▒▒▒▒▒▀▀▀▒▒▒▒▒▒▒▒░░░░▒▒▒▒▌  HAPPY TIME
─▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐  
──▀▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▒▒▒▒▌ <#{EMAIL_SECRET}>
────▀▄▒▒▒▒▒▒▒▒▒▒▄▄▄▀▒▒▒▒▄▀
───▐▀▒▀▄▄▄▄▄▄▀▀▀▒▒▒▒▒▄▄▀
──▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▀▀

    PROTECTED

    MAX_CLIENT_BY_ADDR = 5
    MAX_LOADING_TIME = 10
    MAX_EXECUTION_TIME = 5
    MAX_FIRMWARE_SIZE = 0x800
    MEMORY_SIZE = 1 << 16
    UNMAPPED_REGION = (0x800 .. 0xFFF)
    UART_TX_REGISTER = 0xFC00
    HALT_CPU_REGISTER = 0xFC10
    TSC_REGISTER = 0xFC12
    EXCEPTION_CONTEXT = 0xFC20

    EXCEPTION_MESSAGES = 
    {
        bad_insn: "Invalid instruction",
        unaligned_insn: "Unaligned instruction",
        bkpt: "Breakpoint",
        access_violation: "Memory access violation",
        watchdog: "Watchdog timer expired",
        div_by_zero: "Division by zero",
        privileged: "Privileged instruction",
    }
    @@instances = []

    attr_reader :client
    def initialize(client, peer)
        @firmware_format = :hex
        @creation_time = Time.now
        @client = client
        @peer = peer
        @@instances.push(self)
        puts "[%s] Created new emulator instance for %s." % [ Time.now.to_s, self.remote_ip ]
    end

    def self.instances
        @@instances
    end

    def self.kill_all(ip = nil)
        @@instances.each {|emu| (ip.nil? or emu.remote_ip == ip) and emu.kill}
    end

    def remote_ip
        @peer.ip_address
    end

    def kill(reason = '')
        unless @client.closed?
            puts "[%s] Closing connection with %s (reason: %s)." % [ Time.now.to_s, self.remote_ip, reason.inspect ]
            @client.puts "CLOSING: #{reason}." unless reason.empty?
            sleep 2.0
            @client.close
        end
        @@instances.delete(self)
    end

    def run
        fail("Too many connections.") if @@instances.count {|emu| emu.remote_ip == self.remote_ip } > MAX_CLIENT_BY_ADDR
        load_firmware

        @registers = Array.new(16, 0x0000)
        @pc = ROM_REGION.begin
        @mode = :kernel
        @fault_addr = 0x0000
        @flags = { z:0, s:0 }
        @cpu_halted = false
        @ticks = 0

        begin
            begin
                Timeout.timeout(MAX_EXECUTION_TIME) {
                    while not @cpu_halted do
                        opcode, args = parse_instruction(@pc)
                        @pc = execute_insn(opcode, args)
                    end
                }
            rescue Timeout::Error
                exception(:watchdog)
            end

        rescue EmulatorException => exc
            crash_report(exc)
            raise

        rescue Exception => e
            STDERR.puts "[%s] Bug detected: %s" % [ Time.now.to_s, e.message.inspect ]
            STDERR.puts "#{e.backtrace.join($/)}"
            crash_report(e)
            raise
        end
    end

    private

    def exception(type, at = nil)
        @fault_addr = at unless at.nil?
        raise EmulatorException, EXCEPTION_MESSAGES[type]
    end

    def overlap(range1, range2)
        not (range1.begin > range2.end or range1.end < range2.begin)
    end

    def read_access_check(addr, size)
        addr_start = addr
        addr_end = (addr + size - 1) & 0xffff
        fail if addr_end < addr_start
        
        access_range = Range.new(addr_start, addr_end)
        exception(:access_violation, addr) if addr_start >= PROTECTED_MEMORY_REGION.begin and @mode != :kernel
        exception(:access_violation, addr) if overlap(UNMAPPED_REGION, access_range)
    end

    def write_access_check(addr, size)
        addr_start = addr
        addr_end = (addr + size - 1) & 0xffff
        fail if addr_end < addr_start
        
        access_range = Range.new(addr_start, addr_end)
        exception(:access_violation, addr) if addr_start >= PROTECTED_MEMORY_REGION.begin and @mode != :kernel
        exception(:access_violation, addr) if overlap(UNMAPPED_REGION, access_range)
        exception(:access_violation, addr) if overlap(ROM_REGION, access_range)
    end

    def memory_read(addr, size)
        read_access_check(addr, size)

        return [ (@ticks >> 8) & 0xff ] if addr == TSC_REGISTER and size == 1
        return [ @ticks & 0xff ] if addr == TSC_REGISTER+1 and size == 1
        
        @memory[addr, size]
    end

    def memory_write(addr, value)
        size = value.size
        write_access_check(addr, size)

        if addr == UART_TX_REGISTER and value.size == 1
            @client.syswrite(value[0].chr)
            @client.flush
        elsif addr == HALT_CPU_REGISTER and value.size == 1 and value[0] & 1 != 0
            @cpu_halted = true
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
            when 3 then 'xor'
            when 4 then 'or'
            when 5 then 'and'
            when 6 then 'add'
            when 7 then 'sub'
            when 8 then 'mul'
            when 9 then 'div'
            when 10 then 'jcc'
            when 11 then 'jmp'
            when 12
                ((insn[0] >> 3) & 1).zero? ? 'call' : 'syscall'
            when 13
                ((insn[0] >> 3) & 1).zero? ? 'ret' : 'sysret'
            when 14 then 'ldr'
            when 15 then 'str'
                else exception(:bad_insn)
            end

        case opcode
        when 'mov.lo', 'mov.hi'
            args.push(insn[0] & 0xf) # destination register
            args.push(insn[1])       # 8 bit immediate

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

        when 'jmp', 'call'
            args.push(((insn[0] & 3) << 8) | insn[1]) # destination offset: 10 bits
            if args.last[9] == 1
                args[-1] |= 0xfc00 # sign extend
            end

        when 'syscall'
            args.push(insn[1])

        when 'ret'
            args.push(insn[1] & 0xf)

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

    def save_context
        @memory[EXCEPTION_CONTEXT, 2 * @registers.size] = @registers.pack('n*').unpack('C*')
        flags = 0
        flags |= 1 if @flags[:z]
        flags |= 2 if @flags[:s]
        @memory[EXCEPTION_CONTEXT + 2 * @registers.size, 2] = [ ((@pc + 2) & 0xffff) ].pack('n').unpack('C*')
        @memory[EXCEPTION_CONTEXT + 2 * @registers.size + 2, 2] =  [ flags ].pack('n').unpack('C*')
    end

    def restore_context
        @registers.replace @memory[EXCEPTION_CONTEXT, 2 * @registers.size].pack('C*').unpack('n*')
        flags = @memory[EXCEPTION_CONTEXT + 2 * @registers.size + 2, 2].pack('C*').unpack('n')[0]
        @flags[:z] = (flags & 1)
        @flags[:s] = ((flags >> 1) & 1)
        @mode = :user

        @memory[EXCEPTION_CONTEXT + 2 * @registers.size, 2].pack('C*').unpack('n')[0]
    end

    def execute_insn(opcode, args)
        STDERR.puts "Executing #{@mode}@#{@pc.to_s(16)} #{opcode} #{args.join(', ')}" if $DEBUG
        @ticks += 1

        case opcode
            when 'jmp'
                return (@pc + args[0]) & 0xffff
            when 'call'
                @registers[15] = (@pc + 2) & 0xffff
                return (@pc + args[0]) & 0xffff
            when 'syscall'
                save_context()
                @registers[0] = args[0]
                @mode = :kernel
                return ROM_REGION.begin
            when 'sysret'
                exception(:privileged) if @mode != :kernel
                return restore_context()
            when 'ret'
                return @registers[args[0]]
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
                byte = memory_read((@registers[args[1]] + @registers[args[2]]) & 0xffff, 1)[0]
                @registers[args[0]] &= 0xff00
                @registers[args[0]] |= byte
            when 'str'
                byte = @registers[args[0]] & 0x00ff
                memory_write((@registers[args[1]] + @registers[args[2]]) & 0xffff, [ byte ])

        end

        STDERR.puts @registers.map.with_index{|r,i| "r#{i}:#{r.to_s(16)}"}.inspect if $DEBUG
        (@pc + 2) & 0xffff
    end

    def update_flags(result)
        @flags[:z] = (result != 0x0000) ? 0 : 1
        @flags[:s] = (result & 0x8000 == 0) ? 0 : 1
    end

    def load_firmware
        fw_data = ''
        Timeout.timeout(MAX_LOADING_TIME) do
            fw_data =
                case @firmware_format
                when :raw
                    load_raw_firmware
                when :hex
                    load_hex_firmware 
                end
        end

        @memory = Array.new(MEMORY_SIZE, 0)
        @memory[PROTECTED_MEMORY_REGION] = PROTECTED_MEMORY
        @memory[ROM_REGION.begin, ROM.size] = ROM
        @memory[0, fw_data.size] = fw_data.bytes
    end

    def load_raw_firmware
        fw_size = @client.read(2)
        fail("invalid packet size") if fw_size.length != 2

        crc = @client.read(4)
        fail("invalid checksum") if crc.length != 4
        
        fw_size = fw_size.unpack('n')[0]
        fail("invalid firmware size") if fw_size.zero? or fw_size > MAX_FIRMWARE_SIZE

        fw_data = @client.read(fw_size)
        fail("not enough data") if fw_data.length != fw_size

        fail("bad checksum") if Zlib.crc32(fw_data) != crc.unpack('N')[0]
        fw_data
    end

    def load_hex_firmware
        eof = false
        fw_data = []

        until eof
            fail("invalid line") if not (start = @client.read(1)) or start != ?:
            hdr = @client.read(8)
            fail("invalid line") unless hdr.upcase =~ /^([0-9A-F]{2})([0-9A-F]{4})([0-9A-F]{2})$/

            count, addr, type = $~.captures.map(&:hex) 
            fail("invalid firmware address") if addr + count > MAX_FIRMWARE_SIZE
            fail("invalid record type") if not (0..1).include?(type)
            eof = (type == 1)

            data = @client.read((count + 1) * 2 + (eof ? 0 : 1))
            fail("invalid line") unless data.upcase =~ /^([0-9A-F]{#{count*2}})([0-9A-F]{2})/

            block = [ $1 ].pack('H*').bytes
            cksum = $2.hex

            fail("bad checksum") if -([hdr].pack('H*').bytes + block).inject(0,&:+) & 0xff != cksum
            fw_data[addr, block.size] = block
        end

        fw_data.map(&:to_i).pack('C*')
    end

    def crash_report(exception)
        @client.puts("-- Exception occurred at %04X: #{exception.message}." % @pc)
        dump_registers 
    end
    
    def dump_registers
        @client.puts <<-REGS
   r0:#{"%04X" % @registers[0]}     r1:#{"%04X" % @registers[1]}    r2:#{"%04X" % @registers[2]}    r3:#{"%04X" % @registers[3]}
   r4:#{"%04X" % @registers[4]}     r5:#{"%04X" % @registers[5]}    r6:#{"%04X" % @registers[6]}    r7:#{"%04X" % @registers[7]}
   r8:#{"%04X" % @registers[8]}     r9:#{"%04X" % @registers[9]}   r10:#{"%04X" % @registers[10]}   r11:#{"%04X" % @registers[11]}
  r12:#{"%04X" % @registers[12]}    r13:#{"%04X" % @registers[13]}   r14:#{"%04X" % @registers[14]}   r15:#{"%04X" % @registers[15]}
   pc:#{"%04X" % @pc} fault_addr:#{"%04X" % @fault_addr} [S:#{@flags[:s]} Z:#{@flags[:z]}] Mode:#{@mode.to_s}
        REGS
    end
end

def drop_privileges(user)
    current_user = Etc.getpwuid.name
    return if current_user == user

    user_exists = !!Etc.getpwnam(user) rescue false
    if Etc.getpwuid.uid != 0 or not user_exists
        STDERR.puts "[-] Warning: Cannot drop privileges to user #{user}."
        STDERR.puts "[-] Running under user #{current_user} instead."
        return
    end

    Process::UID.change_privilege(user)
end

def run_server(iface, port)
    server = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM)
    server.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
    server.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, true)
    server.bind(Addrinfo.tcp(iface, port))
    server.listen(10)

    loop do
        Thread.start(server.accept) do |client, peer|
            emu = Emulator.new(client, peer)
            begin
                emu.run
            rescue Exception => exc
                emu.kill(exc.message)
            ensure
                emu.kill
            end
        end
    end
end

drop_privileges(RUN_AS_USER)

trap(:INT) {
    exit
}

running_processes = 0
loop do
    while running_processes < SERVER_POOL_NPROCESS
        Process.fork {
            puts "[%s] New server process spawned, pid %d." % [ Time.now.to_s, $$ ]
            run_server("0.0.0.0", 10101)
        }
        running_processes += 1
    end

    Process.wait
    running_processes -= 1
end

