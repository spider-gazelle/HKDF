require "openssl/hmac"

# HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
module HKDF
  {% begin %}
    VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}
  {% end %}

  # HKDF Extract phase
  def self.extract(salt : Bytes, ikm : Bytes, hash_algo = OpenSSL::Algorithm::SHA256) : Bytes
    OpenSSL::HMAC.digest(hash_algo, salt, ikm)
  end

  # HKDF Expand phase
  def self.expand(prk : Bytes, info : Bytes, length : Int32, hash_algo = OpenSSL::Algorithm::SHA256) : Bytes
    # Determine digest size
    dummy_data = Bytes.new(0)
    digest_size = OpenSSL::HMAC.digest(hash_algo, prk, dummy_data).size

    blocks_needed = (length.to_f / digest_size).ceil
    raise "Derived key too long" if blocks_needed > 0xFF

    t = Bytes.new(0)
    output = Bytes.new(0)
    previous_block = Bytes.new(0)

    (1..blocks_needed).each do |i|
      data_to_hash = previous_block + info + Bytes[i.to_u8]
      previous_block = OpenSSL::HMAC.digest(hash_algo, prk, data_to_hash)
      output = output + previous_block
    end

    output[0, length]
  end

  # Combined HKDF Extract-and-Expand
  def self.derive_key(salt : Bytes, ikm : Bytes, info : Bytes, length : Int32, hash_algo = OpenSSL::Algorithm::SHA256) : Bytes
    prk = extract(salt, ikm, hash_algo)
    expand(prk, info, length, hash_algo)
  end
end
