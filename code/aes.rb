require 'openssl'
require 'forwardable'

module AES

  class Base
    attr_reader :key

    def initialize(key)
      @key = key
      cipher = AES.create_cipher(key)
      yield cipher
      cipher.key = @key
      cipher.padding = 0
      @impl = cipher
    end

    def block_size
      @impl.block_size
    end

    def encrypt_block(block)
      @impl.update(block)
    end
    alias_method :decrypt_block, :encrypt_block

  end

  class EncryptorAlgorithm
    extend Forwardable

    def initialize(key)
      @impl = Base.new(key) { |cipher| cipher.encrypt }
    end

    def_delegators :@impl, :key, :block_size, :encrypt_block
  end

  class DecryptorAlgorithm
    extend Forwardable

    def initialize(key)
      @impl = Base.new(key) { |cipher| cipher.decrypt }
    end

    def_delegators :@impl, :key, :block_size, :decrypt_block
  end

  module_function

  def create_cipher(key)
    OpenSSL::Cipher::AES.new(key.bytesize * 8, :ECB)
  end

end

