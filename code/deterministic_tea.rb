require_relative 'tea'
require_relative 'padding'
require_relative 'string_refinements'

using StringRefinements

module Deterministic

  class Encryptor
    attr_reader :algorithm, :padding

    def initialize(algorithm:, padding:)
      @algorithm = algorithm
      @padding = padding
    end

    def encrypt(plain_text)
      padding.
        apply_to(plain_text).
        each_block(algorithm.block_size).
        map { |block|
          algorithm.encrypt_block(block)
        }.join
    end
  end

  class Decryptor
    attr_reader :algorithm, :padding

    def initialize(algorithm:, padding:)
      @algorithm = algorithm
      @padding = padding
    end

    def decrypt(encrypted)
      decrypted = encrypted.
          each_block(algorithm.block_size).
          map { |block|
            algorithm.decrypt_block(block)
          }.join

      padding.strip_from(decrypted)
    end
  end

end

key = "\x00" * TEA::KEY_SIZE
plaintext = "zickzack" * 3

encryptor_algorithm = TEA::EncryptorAlgorithm.new(key)
padding = Padding::PKCS5.new(encryptor_algorithm.block_size)
encryptor = Deterministic::Encryptor.new(algorithm: encryptor_algorithm, padding: padding)

encrypted = encryptor.encrypt(plaintext)

puts encrypted.to_hex.each_block(16).to_a.join(" ")

decryptor_algorithm = TEA::DecryptorAlgorithm.new(key)
padding = Padding::PKCS5.new(decryptor_algorithm.block_size)
decryptor = Deterministic::Decryptor.new(algorithm: decryptor_algorithm, padding: padding)

decrypted = decryptor.decrypt(encrypted)

puts decrypted
