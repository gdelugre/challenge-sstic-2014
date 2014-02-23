#!/usr/bin/env ruby

require 'pp'

exit(1) if ARGV.length != 2

TRACE_FILE = ARGV[0]
OUTPUT_FILE = ARGV[1]

ADB_COMMANDS = 
{
    0x434e5953 => :sync,
    0x4e584e43 => :cnxn,
    0x4e45504f => :open,
    0x59414b4f => :okay,
    0x45534c43 => :clse,
    0x45545257 => :wrte,
}

def sum(data)
    data.bytes.inject(0) {|a,b| a+b} & 0xffff_ffff
end

def parse_adb_hdr(data)
    cmd, arg0, arg1, length, crc, magic = data.unpack("V6")

    fail "Unknown command: #{data[0,4].inspect}" unless ADB_COMMANDS.include?(cmd)
    fail "Bad magic" unless cmd == magic ^ 0xffff_ffff

    {
        cmd: ADB_COMMANDS[cmd],
        arg0: arg0,
        arg1: arg1,
        length: length,
        crc: crc
    }
end

packets = []
pending_data = 0

File.read(TRACE_FILE).lines
    .delete_if {|line| line =~ /<|>/ or line.index('=').nil?}
    .map { |line|
        line.chomp!
        direction = (line.split[3][0,2] == "Bi") ? :input : :output
        data = [ line[line.index('=')+1 .. -1].gsub(' ','') ].pack 'H*'

        { direction: direction, data: data }
    }
    .each { |blk|
        if pending_data == 0
            hdr = parse_adb_hdr(blk[:data])
            packets.push(hdr: hdr, direction: blk[:direction])
            pending_data = hdr[:length]
        else
            fail "Bad data size" if blk[:data].size != pending_data
            fail "Bad checksum" if sum(blk[:data]) != packets.last[:hdr][:crc]
            packets.last[:data] = blk[:data]
            pending_data = 0
        end
    }

first_write = packets.index { |pkt|
    pkt[:hdr][:cmd] == :wrte and pkt[:direction] == :output and pkt[:data] =~ /\x7FELF/
} or fail "Can't find first write packet"

last_write = packets[first_write .. -1].index { |pkt|
    pkt[:hdr][:cmd] == :wrte and pkt[:data][0,4] == "OKAY"
} or fail "Can't find last write packet"

first_block = packets[first_write][:data]
data_token = first_block.index("DATA")
chunk_size = first_block[data_token+4, 4].unpack("V")[0]
first_block.slice!(0, data_token+8)

payload = ""

packets[first_write, last_write].select {|pkt|
    pkt[:direction] == :output and pkt[:hdr][:cmd] == :wrte
}.map {|pkt| 
    if pkt[:data].size < chunk_size
        payload << pkt[:data]
        chunk_size -= pkt[:data].size
    else
        payload << pkt[:data][0, chunk_size]
        pkt[:data].slice!(0, chunk_size)
        fail "Expected DATA token" if pkt[:data].size > 8 and pkt[:data][0, 4] != "DATA"
        
        chunk_size = pkt[:data][4, 4].unpack('V')[0]
        pkt[:data].slice!(0,8)

        payload << pkt[:data]
        chunk_size -= pkt[:data].size
    end
}

File.write(OUTPUT_FILE, payload)
