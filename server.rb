require 'socket'

# header_bitmap = [
#   [:qid, 16],
#   [:qr, 1],
#   [:opcode, 4],
#   [:aa, 1],
#   [:tc, 1],
#   [:rd, 1],
#   [:ra, 1],
#   [:z, 3],
#   [:rcode, 4],
#   [:qdcount, 16],
#   [:ancount, 16],
#   [:nscount, 16],
#   [:arcount, 16],
# ]

def ip_to_32(str)
  str.split('.').inject([]) { 
    |shifted_parts, part| shifted_parts << (part.to_i << (24 - shifted_parts.length*8)) 
  }.inject(0) { 
    |bits, part| bits |= part
  }
end

s = UDPSocket.new
s.bind(nil, 2111)
5.times do
  
  buffer, sender = s.recvfrom(1024)
  
  qid, flags1, flags2, qdcount, ancount, nscount, arcount = buffer.unpack("nCCn4")

  puts "ID: #{qid}"
  puts "Flags: #{flags1.to_s 2} #{flags2.to_s 2}"
  puts "qdcount: #{qdcount}"
  puts "ancount: #{ancount}"
  puts "nscount: #{nscount}"
  puts "arcount: #{arcount}"

  # Parse out the domain from the query section
  domain_fields = []
  query_data = []
  offset = 12 # end of header section, start of qname section
  while (len = buffer.unpack("@#{offset}c")[0]) != 0
    query_data << [len, 8, 'c']
    offset += 1
    field_string = buffer.unpack("@#{offset}a#{len}")[0]
    domain_fields << field_string
    query_data << [field_string, 8*len, "a#{len}"]
    offset += len
  end
  query_data << [0, 8, "c"]
  offset += 1 # move to start of qtype section
  
  qtype, qclass = buffer.unpack("@#{offset}n2")
  
  query_data << [qtype, 16, "n"]
  query_data << [qclass, 16, "n"]
  
  qname = domain_fields.join('.')
  
  puts "qname: #{qname}"
  puts "qtype: #{qtype}"
  puts "qclass: #{qclass}"
  
  
  # response generation
  
  # mask qr, aa, tc, ra, and rcode fields, leave id alone
  flags1_mask = 0b01111001
  flags2_mask = 0b01110000
  
  flags1_set = 0b10000100
   
  new_flags1 = (flags1 & flags1_mask) | flags1_set
  new_flags2 = (flags2 & flags2_mask)
  
  header_data = []
  header_data << [qid, 16, 'n']
  header_data << [new_flags1, 8, 'C']
  header_data << [new_flags2, 8, 'C']
  header_data << [qdcount, 16, 'n']
  header_data << [1, 16, 'n'] # we now have 1 answer
  header_data << [nscount, 16, 'n']
  header_data << [arcount, 16, 'n']
  
  # query section
  
  # query_data
  
  # answer section
  
  answer_data = []
  answer_data << [0b1100000000001100, 16, 'n'] # pointer to the name record in the question section
  #answer_data += query_data[0..(query_data.length-2)]
  answer_data << [1, 16, 'n'] # type
  answer_data << [1, 16, 'n'] # class
  answer_data << [512, 32, 'N'] # ttl
  answer_data << [4, 16, 'n'] # RDLENGTH is 4 cuz we are sending an IP
  answer_data << [ip_to_32("127.0.0.1"), 32, 'N'] # always respond 127.0.0.1
  
  data = header_data + query_data + answer_data
  puts data.inspect
  data_buff = []
  format = ''
  data.each do |b|
    data_buff << b[0]
    format << b[2]
  end
  
  puts format
  
  resp = data_buff.pack(format)
  puts resp
  puts sender.inspect
  
  s.send(resp, 0, sender[3], sender[1])
  
end