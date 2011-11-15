require 'bit_helpers'

class DnsMessage
  
  include BitHelpers
  
  attr_reader :qid
  attr_reader :flags1, :flags2
  attr_reader :qdcount
  attr_reader :ancount
  attr_reader :nscount
  attr_reader :arcount
  attr_reader :queries
  attr_reader :query_fields
  
  def initialize(options = {})
    @qid = 0
    @flags1 = 0b00000001
    @flags2 = 0b00000000
    @qdcount = 0
    @ancount = 0
    @nscount = 0
    @arcount = 0
    @packet_data = ''
    @queries = []
    @query_fields = []
    @answers = []
    update_packet_data
  end
  
  def self.load(packet)
    obj = self.new
    obj.load(packet)
    obj
  end
  
  bit_attr_accessor :qr, :flags1, 7, :on_update => :update_packet_data
  
  def request!
    self.qr = 0
  end
  
  def response!
    self.qr = 1
  end
  
  bit_attr_accessor :recursion_desired, :flags1, 0, :on_update => :update_packet_data
  alias :rd= :recursion_desired=
  
  bit_attr_accessor :authoritative_answer, :flags1, 2, :on_update => :update_packet_data
  alias :aa= :authoritative_answer=
  
  bit_attr_accessor :truncation, :flags1, 1, :on_update => :update_packet_data
  alias :tc= :truncation=

  bit_attr_accessor :recursion_available, :flags2, 7, :on_update => :update_packet_data
  alias :ra= :recursion_available=
  
  def load(packet)
    @packet_data = packet
    load_packet_data
  end
  
  def header_fields
    tmp = []
    tmp << [@qid, 16, 'n']
    tmp << [@flags1, 8, 'C']
    tmp << [@flags2, 8, 'C']
    tmp << [@qdcount, 16, 'n']
    tmp << [@ancount, 16, 'n']
    tmp << [@nscount, 16, 'n']
    tmp << [@arcount, 16, 'n']
    tmp
  end
  
  def to_bytes
    @packet_data
  end
  alias :to_s :to_bytes
  
  def add_answer(id, type, aclass, ttl, data)
    if data =~ /\d+\.\d+\.\d+\.\d+/
      @answers << {:id => id, :type => type, :class => aclass, :ttl => ttl, :data => ip_to_32(data)}
    else
      @answers << {:id => id, :type => type, :class => aclass, :ttl => ttl, :data => data}
    end
    @ancount += 1
    update_packet_data
  end
  
  def answer_fields
    tmp = []
    @answers.each do |a|
      tmp << [0b1100000000001100, 16, 'n'] # pointer to the name record in the question section TODO - need to support other queries
      tmp << [a[:type], 16, 'n']
      tmp << [a[:class], 16, 'n']
      tmp << [a[:ttl], 32, 'N']
      tmp << [4, 16, 'n'] # RDLENGTH is 4 cuz we are sending an IP TODO - need to support other things
      tmp << [a[:data], 32, 'N']
    end
    tmp
  end
  
  private
    
    def load_packet_data
      load_header_from_packet_data
      load_queries_from_packet_data
    end
    
    def load_header_from_packet_data
      f = @packet_data.unpack("nCCn4")
      @qid = f[0]
      @flags1 = f[1]
      @flags2 = f[2]
      @qdcount = f[3]
      @ancount = f[4]
      @nscount = f[5]
      @arcount = f[6]
    end
    
    def load_queries_from_packet_data
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
        @query_fields += query_data
      end
    end
    
    def update_packet_data
      fields = header_fields + query_fields + answer_fields
      @packet_data = fields_to_bytes(fields)
      true
    end
    
    def fields_to_bytes(data_fields)
      data_buff = []
      format = ''
      data_fields.each do |b|
        data_buff << b[0]
        format << b[2]
      end
      data_buff.pack(format)
    end
    
    def ip_to_32(str)
      str.split('.').inject([]) { 
        |shifted_parts, part| shifted_parts << (part.to_i << (24 - shifted_parts.length*8)) 
      }.inject(0) { 
        |bits, part| bits |= part
      }
    end
  
end