#!/usr/bin/env ruby

#
# Rolls back the LFSR used to encrypt the payload.
#

LFSR_SEED = 0x05B1AD0B11ADDE15
LFSR_POLY = 0xB000000000000001
LFSR_SIZE = 64

def parity(n)
    n.to_s(2).count('1') & 1
end

#
# Assumes the cleartext is padded with zeros.
#
def lfsr_rollback(encrypted)
    
    state = encrypted[-8,8].unpack('Q>')[0].to_s(2).rjust(LFSR_SIZE, '0').reverse.to_i(2)

    ((encrypted.size - 8) * 8 + 1).times do
        bit = (state >> (LFSR_SIZE - 1)) & 1
        state <<= 1
        state &= (1 << LFSR_SIZE) - 1
        state |= parity(state & LFSR_POLY) ^ bit
    end

    puts "[+] Found seed %016X" % state
end

data = File.binread(ARGV[0])
lfsr_rollback(data)
