require 'forwardable'

require_relative 'aes'
require_relative 'tea'
require_relative 'mode'
require_relative 'padding'
require_relative 'string_refinements'

using StringRefinements

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
      map do |block|
        mode.encrypt(
          block: block,
          algorithm: algorithm
        )
      end.join << mode.authenticator_tag
  end

  class BaseEncryptor
    extend Forwardable

    attr_reader :encryptor

    def initialize(algorithm:, mode:, padding: :pkcs5)
      block_size = algorithm.block_size

      @encryptor = Encryptor.new(
        algorithm: algorithm,
        mode: Mode.mode_for(name: mode, block_size: block_size, key: algorithm.key),
        padding: Padding.padding_for(name: padding, block_size: block_size)
      )
    end

    def_delegators :@encryptor, :encrypt, :iv, :mode, :padding, :algorithm
  end

  class TEA < BaseEncryptor

    attr_reader :encryptor

    def initialize(key:, mode:, padding: :pkcs5)
      super(
        algorithm: ::TEA::EncryptorAlgorithm.new(key),
        mode: mode,
        padding: padding
      )
    end
  end

  class AES < BaseEncryptor

    attr_reader :encryptor

    def initialize(key:, mode:, padding: :pkcs5)
      super(
        algorithm: ::AES::EncryptorAlgorithm.new(key),
        mode: mode,
        padding: padding
      )
    end
  end

end
