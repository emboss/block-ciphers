require_relative 'encryptor'
require_relative 'decryptor'
require_relative 'string_refinements'

using StringRefinements

msg = "Attack at dawn!" * 3
key = "\x00" * 16

# Encryption
encryptor_algorithm = TEA::EncryptorAlgorithm.new(key)
block_size = encryptor_algorithm.block_size
padding = Padding::PKCS5.new(block_size)
mode = Mode.mode_for(name: :cbc_hmac, block_size: block_size, key: key)

encryptor = Encryptor.new(
  algorithm: encryptor_algorithm,
  mode: mode,
  padding: padding
)

encrypted = encryptor.encrypt(msg)
puts encrypted.to_hex.each_block(16).to_a.join(" ")

# Decryption
iv = encryptor.iv
decryptor_algorithm = TEA::DecryptorAlgorithm.new(key)
block_size = decryptor_algorithm.block_size
padding = Padding::PKCS5.new(block_size)
mode = Mode.mode_for(name: :cbc_hmac, block_size: block_size, key: key, iv: iv)


decryptor = Decryptor.new(
  algorithm: decryptor_algorithm,
  mode: mode,
  padding: padding
)

decrypted = decryptor.decrypt(encrypted)
puts decrypted

# Modifikation des Ciphertexts führt zum Fehler
encrypted[0] = "\x00"
decrypted = decryptor.decrypt(encrypted)
