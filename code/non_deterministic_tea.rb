require_relative 'tea'
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

key = "\x00" * TEA::KEY_SIZE
plaintext = "zickzack" * 3

encryptor_algorithm = TEA::EncryptorAlgorithm.new(key)
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

puts encrypted.to_hex.each_block(16).to_a.join(" ")

decryptor_algorithm = TEA::DecryptorAlgorithm.new(key)
iv = encryptor.iv

mode = Mode.mode_for(
  name: :cbc,
  block_size: decryptor_algorithm.block_size,
  iv: iv
)
padding = Padding::PKCS5.new(decryptor_algorithm.block_size)

decryptor = NonDeterministic::Decryptor.new(
  algorithm: decryptor_algorithm,
  mode: mode,
  padding: padding
)

decrypted = decryptor.decrypt(encrypted)

puts decrypted
