require_relative 'padding'
require_relative 'uint32'
require_relative 'string_refinements'
require_relative 'errors'

using StringRefinements

module TEA

  DELTA = 0x9e3779b9
  KEY_SIZE = 16 # bytes, 128 bit
  BLOCK_SIZE = 8 # bytes
  ROUNDS = 32

  class EncryptorAlgorithm

    attr_reader :key

    def initialize(key)
      @key = TEA.validate_key(key)
    end

    def block_size
      BLOCK_SIZE
    end

    def encrypt_block(block)
      TEA.encrypt(block, key)
    end

  end

  class DecryptorAlgorithm

    attr_reader :key

    def initialize(key)
      @key = TEA.validate_key(key)
    end

    def block_size
      BLOCK_SIZE
    end

    def decrypt_block(block)
      TEA.decrypt(block, key)
    end
  end

  module_function

  def encrypt(block, key)
    v0, v1 = UInt32.from_string(block)
    sum = 0
    k0, k1, k2, k3 = UInt32.from_string(key)

    ROUNDS.times do
      sum += DELTA

      v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
      v0 = v0 & UInt32::MASK

      v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
      v1 = v1 & UInt32::MASK
    end

    UInt32.to_string([v0, v1])
  end

  def decrypt(block, key)
    v0, v1 = UInt32.from_string(block)
    sum = DELTA << 5
    k0, k1, k2, k3 = UInt32.from_string(key)

    ROUNDS.times do
      v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
      v1 = v1 & UInt32::MASK

      v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
      v0 = v0 & UInt32::MASK

      sum -= DELTA
    end

    UInt32.to_string([v0, v1])
  end

  def valid_key?(key)
    key.bytesize == KEY_SIZE
  end

  def validate_key(key)
    raise Errors::InvalidKey.new("Invalid key") unless valid_key?(key)
    key
  end

end

