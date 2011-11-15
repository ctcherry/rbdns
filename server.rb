require 'socket'
require 'dns_message'

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


s = UDPSocket.new
s.bind(nil, 2111)
while true do
  
  buffer, sender = s.recvfrom(1024)
  
  message = DnsMessage.load(buffer)
  
  puts message.queries.inspect
  
  reply = message.dup
  reply.response!
  
  reply.aa = true
  reply.ra = false
  reply.tc = false
  
  reply.add_answer(1, 1, 1, 512, "127.0.0.1")
  
  s.send(reply.to_bytes, 0, sender[3], sender[1])
  
end