require 'openssl'
require_relative 'string_refinements'

using StringRefinements

msg = "Attack at dawn!" * 3
key = "\x00" * 16

# Encryption
encryptor = OpenSSL::Cipher::AES.new(128, :GCM).encrypt
encryptor.key = key
iv = encryptor.random_iv

encrypted = encryptor.update(msg) + encryptor.final
tag = encryptor.auth_tag

puts encrypted.to_hex

# Decryption
decryptor = OpenSSL::Cipher::AES.new(128, :GCM).decrypt
decryptor.key = key
decryptor.iv = iv
decryptor.auth_tag = tag

decrypted = decryptor.update(encrypted) + decryptor.final
puts decrypted

# Modifikation des Ciphertexts führt zum Fehler
encrypted[0] = "\x00"
decrypted = decryptor.update(encrypted) + decryptor.final
