class DnsResponse < DnsRequest
  
  def initialize(options = {})
    super(options)
    qr = true
  end
  
end