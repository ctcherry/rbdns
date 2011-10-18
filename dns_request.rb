class DnsRequest
  
  attr_reader :qid
  attr_reader :flags1, :flags2
  attr_reader :qdcount
  attr_reader :ancount
  attr_reader :nscount
  attr_reader :arcount
  attr_reader :queries
  attr_reader :queries_data
  
  def initialize(packet)
    @packet_data = packet
    @queries = []
    @queries_data = []
    parse
  end
  
  def parse
    parse_header
    parse_queries
  end
  
  def parse_header
    @qid, @flags1, @flags2, @qdcount, @ancount, @nscount, @arcount = @packet_data.unpack("nCCn4")
  end
  
  def parse_queries
    offset = 12 # byte offset, end of header section, start of query section
    
    qdcount.times do |qi|
      # Parse out the domain from the query section
      domain_fields = []
      query_data = []
      while (len = @packet_data.unpack("@#{offset}c")[0]) != 0
        query_data << [len, 8, 'c']
        offset += 1
        field_string = @packet_data.unpack("@#{offset}a#{len}")[0]
        domain_fields << field_string
        query_data << [field_string, 8*len, "a#{len}"]
        offset += len
      end
      query_data << [0, 8, "c"]
      offset += 1 # move to start of qtype section

      qtype, qclass = @packet_data.unpack("@#{offset}n2")

      query_data << [qtype, 16, "n"]
      query_data << [qclass, 16, "n"]

      offset += 4

      qname = domain_fields.join('.')
      self.queries << {:qname => qname, :qtype => qtype, :qclass => qclass}
      @queries_data += query_data
    end
  end
  
end