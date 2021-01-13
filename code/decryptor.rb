require 'forwardable'

require_relative 'aes'
require_relative 'tea'
require_relative 'mode'
require_relative 'padding'
require_relative 'string_refinements'
require_relative 'errors'

using StringRefinements

class Decryptor

  attr_reader :algorithm, :mode, :padding

  def initialize(algorithm:, mode:, padding:)
    @algorithm = algorithm
    @mode = mode
    @padding = padding
  end

  def iv
    mode.iv
  end

  def decrypt(encrypted)
    encrypted, authenticator_tag = mode.retrieve_tag(encrypted)

    decrypted = padding.strip_from(
      encrypted.
        each_block(algorithm.block_size).
        map do |block|
          mode.decrypt(
            block: block,
            algorithm: algorithm
          )
        end.join
    )

    mode.authenticate(authenticator_tag)

    decrypted
  end

  class BaseDecryptor
    extend Forwardable

    attr_reader :decryptor

    def initialize(algorithm:, mode:, iv: nil, padding: :pkcs5)
      iv_required?(mode, iv)

      block_size = algorithm.block_size

      @decryptor = Decryptor.new(
        algorithm: algorithm,
        mode: Mode.mode_for(name: mode, block_size: block_size, key: algorithm.key, iv: iv),
        padding: Padding.padding_for(name: padding, block_size: block_size)
      )
    end

    def_delegators :@decryptor, :decrypt, :mode, :padding, :algorithm

    private

    def iv_required?(mode, iv)
      case mode
      when :ecb, :ECB then return
      else raise Errors::IVMissing.new("No IV provided for mode: #{mode}") unless iv
      end
    end
  end

  class TEA < BaseDecryptor

    attr_reader :decryptor

    def initialize(key:, mode:, iv: nil, padding: :pkcs5)
      super(
        algorithm: ::TEA::DecryptorAlgorithm.new(key),
        mode: mode,
        iv: iv,
        padding: padding
      )
    end
  end

  class AES < BaseDecryptor

    attr_reader :decryptor

    def initialize(key:, mode:, iv: nil, padding: :pkcs5)
      super(
        algorithm: ::AES::DecryptorAlgorithm.new(key),
        mode: mode,
        iv: iv,
        padding: padding
      )
    end
  end

end
