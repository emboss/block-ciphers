require_relative 'encryptor'
require_relative 'decryptor'
require_relative 'string_refinements'

using StringRefinements

msg = "Attack at dawn!" * 3
key = "\x00" * 16

# Encryption
encryptor = Encryptor::TEA.new(
  key: key,
  mode: :cbc_hmac
)

encrypted = encryptor.encrypt(msg)
puts encrypted.to_hex.each_block(16).to_a.join(" ")

# Decryption
iv = encryptor.iv

decryptor = Decryptor::TEA.new(
  key: key,
  mode: :cbc_hmac,
  iv: iv
)

decrypted = decryptor.decrypt(encrypted)
puts decrypted

