require 'securerandom'
require 'openssl'

require_relative 'string_refinements'
require_relative 'errors'

using StringRefinements

module Mode

  module ECB

    module_function

    def encrypt(block:, algorithm:)
      algorithm.encrypt_block(block)
    end

    def decrypt(block:, algorithm:)
      algorithm.decrypt_block(block)
    end

    def authenticator_tag
      ""
    end

    def retrieve_tag(encrypted)
      [encrypted, nil]
    end

    def authenticate(authenticator_tag); end

    def iv; end
  end

  class CBC

    attr_reader :iv

    def initialize(block_size, iv)
      @iv = iv || SecureRandom.bytes(block_size)
      @last_cipher_text_block = @iv
    end

    def encrypt(block:, algorithm:)
      xored = block.xor(@last_cipher_text_block)
      @last_cipher_text_block = algorithm.encrypt_block(xored)
    end

    def decrypt(block:, algorithm:)
      decrypted = algorithm.decrypt_block(block)
      tmp = @last_cipher_text_block
      @last_cipher_text_block = block
      decrypted.xor(tmp)
    end

    def authenticator_tag
      ""
    end

    def retrieve_tag(encrypted)
      [encrypted, nil]
    end

    def authenticate(authenticator_tag); end
  end

  class CBC_HMAC
    attr_reader :iv, :hmac

    TAG_SIZE = 32 # bytes, 256 bit

    def initialize(block_size, key, iv)
      @iv = iv || SecureRandom.bytes(block_size)
      @hmac = OpenSSL::HMAC.new(key, OpenSSL::Digest::SHA256.new)
      @last_cipher_text_block = @iv
    end

    def encrypt(block:, algorithm:)
      xored = block.xor(@last_cipher_text_block)
      encrypted_block = algorithm.encrypt_block(xored)
      hmac.update(encrypted_block)
      @last_cipher_text_block = encrypted_block
    end

    def decrypt(block:, algorithm:)
      hmac.update(block)
      decrypted = algorithm.decrypt_block(block)
      tmp = @last_cipher_text_block
      @last_cipher_text_block = block
      decrypted.xor(tmp)
    end

    def authenticator_tag
      hmac.digest
    end

    def retrieve_tag(encrypted)
      [encrypted[0...-TAG_SIZE], encrypted[-TAG_SIZE..-1]]
    end

    def authenticate(tag_to_compare)
      unless authenticator_tag.secure_equals?(tag_to_compare)
        raise Errors::TagMismatch.new("Tag mismatch")
      end
    end

  end

  module_function

  def mode_for(name:, block_size: nil, key: nil, iv: nil)
    case name
    when :ecb, :EBC then ECB
    when :cbc, :CBC then CBC.new(block_size, iv)
    when :cbc_hmac, :CBC_HMAC then CBC_HMAC.new(block_size, key, iv)
    end
  end

end
