require_relative 'aes'
require_relative 'padding'
require_relative 'mode'
require_relative 'string_refinements'

using StringRefinements

module NonDeterministic

  class Encryptor
    attr_reader :algorithm, :mode, :padding

    def initialize(algorithm:, mode:, padding:)
      @algorithm = algorithm
      @mode = mode
      @padding = padding
    end

    def iv
      mode.iv
    end

    def encrypt(plain_text)
      padding.
        apply_to(plain_text).
        each_block(algorithm.block_size).
        map { |block|
          mode.encrypt(
            block: block,
            algorithm: algorithm
          )
        }.join
    end
  end

  class Decryptor
    attr_reader :algorithm, :mode, :padding

    def initialize(algorithm:, mode:, padding:)
      @algorithm = algorithm
      @mode = mode
      @padding = padding
    end

    def decrypt(encrypted)
      decrypted = encrypted.
          each_block(algorithm.block_size).
          map { |block|
            mode.decrypt(
              block: block,
              algorithm: algorithm
            )
          }.join

      padding.strip_from(decrypted)
    end
  end

end

key = "\x00" * 16 # AES-128
plaintext = "zickzack" * 4

encryptor_algorithm = AES::EncryptorAlgorithm.new(key)
# IV wird automatisch generiert
mode = Mode.mode_for(
  name: :cbc,
  block_size: encryptor_algorithm.block_size
)
padding = Padding::PKCS5.new(encryptor_algorithm.block_size)

encryptor = NonDeterministic::Encryptor.new(
  algorithm: encryptor_algorithm,
  mode: mode,
  padding: padding
)

encrypted = encryptor.encrypt(plaintext)

puts encrypted.to_hex.each_block(32).to_a.join(" ")

iv = encryptor.iv
cipher = OpenSSL::Cipher::AES.new(128, :CBC)
cipher.decrypt
cipher.key = key
cipher.iv = iv

decrypted = cipher.update(encrypted) + cipher.final

puts decrypted
