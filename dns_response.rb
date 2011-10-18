class DnsResponse
  
  def initialize(dns_request)
    @dns_request = dns_request
    @flags1_mask = 0b01111001
    @flags1_set  = 0b10000000 # qr set to one cuz this is a response
    
    @flags2_mask = 0b01110000
    @flags2_set  = 0b00000000
    
    @answers = []
  end
  
  def aa=(value)
    @flags1_set = set_bit_of_byte(@flags1_set, 2, value)
  end
  
  def tc=(value)
    @flags1_set = set_bit_of_byte(@flags1_set, 1, value)
  end
  
  def ra=(value)
    @flags2_set = set_bit_of_byte(@flags2_set, 7, value)
  end
  
  def add_answer(id, type, aclass, ttl, data)
    if @answers.length >= @dns_request.qdcount
      raise "Cant add another answer"
      return false
    end
    if data =~ /\d+\.\d+\.\d+\.\d+/
      @answers << {:id => id, :type => type, :class => aclass, :ttl => ttl, :data => ip_to_32(data)}
    else
      @answers << {:id => id, :type => type, :class => aclass, :ttl => ttl, :data => data}
    end
  end
  
  def to_bytes
    data = header_data + @dns_request.queries_data + answer_data
    data_buff = []
    format = ''
    data.each do |b|
      data_buff << b[0]
      format << b[2]
    end
    data_buff.pack(format)
  end
  
  def to_s
    to_bytes
  end
  
  private
  
    def header_data

      new_flags1 = (@dns_request.flags1 & @flags1_mask) | @flags1_set
      new_flags2 = (@dns_request.flags2 & @flags2_mask) | @flags2_set

      tmp = []
      tmp << [@dns_request.qid, 16, 'n']
      tmp << [new_flags1, 8, 'C']
      tmp << [new_flags2, 8, 'C']
      tmp << [@dns_request.qdcount, 16, 'n']
      tmp << [@answers.length, 16, 'n'] # we now have 1 answer
      tmp << [@dns_request.nscount, 16, 'n']
      tmp << [@dns_request.arcount, 16, 'n']
      tmp
    end

    def answer_data
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
  
    def ip_to_32(str)
      str.split('.').inject([]) { 
        |shifted_parts, part| shifted_parts << (part.to_i << (24 - shifted_parts.length*8)) 
      }.inject(0) { 
        |bits, part| bits |= part
      }
    end
    
    def set_bit_of_byte(byte, bit_offset, value)
      mask = (1 << bit_offset) ^ ((1 << 8) - 1)
      if value === false || value == 0
        set = 0
      else
        set = (1 << bit_offset)
      end
      byte = (byte & mask) | set
      byte
    end
  
end