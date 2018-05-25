#!/usr/bin/env ruby

inf = ARGV[0]
outf = ARGV[1]

data = File.read(inf).bytes

offset = 0
output = ""

while true do
    l = data[0]
    r = data[1]

    if not l or not r then break end
   
    #nyte16 = (((l << offset) << 8) | (r << offset)) & 0b1111111110000000
    nyte16 = ((((l << offset) << 8) | (r << offset)) & 0b1111111110000000) >> 7
    output << [nyte16].pack("s>")

    data.shift
    if offset == 7
        data.shift
    end
    offset += 1
    offset %= 8
end

File.write(outf, output)
