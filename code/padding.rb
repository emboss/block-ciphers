require_relative 'errors'

module Padding

  class PKCS5

    attr_reader :block_size

    def initialize(block_size)
      @block_size = block_size
    end

    def apply_to(plain_text)
      num_padding = block_size - (plain_text.bytesize % block_size)
      padding = num_padding.chr * num_padding
      "#{plain_text}#{padding}"
    end

    def strip_from(decrypted)
      num_padding = decrypted.byteslice(-1).ord
      decrypted.byteslice(0, decrypted.bytesize - num_padding)
    end

  end

  class None

    attr_reader :block_size

    def initialize(block_size)
      @block_size = block_size
    end

    def apply_to(plain_text)
      plain_text
    end

    def strip_from(decrypted)
      decrypted
    end

  end

  module_function

  def padding_for(name:, block_size:)
    case name
    when :none, :NONE then None.new(block_size)
    when :pkcs5, :PKCS5 then PKCS5.new(block_size)
    end
  end

end
