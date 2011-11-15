module BitHelpers
  
  def self.included(base)
    base.send(:extend, ClassMethods)
    base.send(:include, InstanceMethods)
  end
  
  module ClassMethods
    def bit_attr_accessor(getter, byte_var_name, position, options = {})
      setter = "#{getter.to_s}=".to_sym
      define_method(setter) do |value|
        res = set_bit_of_byte(send(byte_var_name), position, value)
        instance_variable_set("@#{byte_var_name}", res)
        send(options[:on_update]) if options[:on_update]
        res
      end
      
      define_method(getter) do |value|
        get_bit_of_byte(send(byte_var_name), position, value)
      end
    end
  end
  
  module InstanceMethods
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
    
    def get_bit_of_byte(byte, bit_offset)
      tmp = set_bit_of_byte(byte, bit_offset, true)
      (tmp == byte)
    end
  end
  
end