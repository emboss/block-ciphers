module StringRefinements
  refine String do
    def xor(other)
      raise "Length mismatch" unless bytesize == other.bytesize
      each_byte.zip(other.each_byte).map do |(a, b)|
        a ^ b
      end.map(&:chr).join("")
    end

    def secure_equals?(other)
      return false unless bytesize == other.bytesize
      (each_byte.zip(other.each_byte).inject(0) { |memo, (a, b)|
        memo | (a ^ b)
      }) == 0
    end

    def each_block(block_size, &blk)
      raise "Length is not a multiple of #{block_size}" unless bytesize % block_size == 0

      offset = 0
      enum = Enumerator.new do |yielder|
        while offset < bytesize
          sliced = byteslice(offset, block_size)
          yielder << sliced
          offset += block_size
        end
      end

      return enum unless block_given?
      enum.each(&blk)
    end

    def to_hex
      unpack('H*').first
    end
  end
end

