module UInt32

  MASK = 0xFF_FF_FF_FF

  module_function

  def from_string(s)
    s.unpack('N*')
  end

  def to_string(uint32s)
    uint32s.pack('N*')
  end
end
