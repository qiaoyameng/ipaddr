# frozen_string_literal: true

require 'openssl'

class IPAddr
  # IPAddr::CryptoPAn implements the Crypto-PAn prefix-preserving IP
  # address anonymization algorithm (Xu, Fan, Ammar & Moon,
  # "Prefix-Preserving IP Address Anonymization: Measurement-based
  # Security Evaluation and a New Cryptography-based Scheme", ICNP 2002).
  #
  # A CryptoPAn instance is built from a fixed 32-byte key.  The first
  # 16 bytes are the AES-128 key used by the underlying pseudorandom
  # function +f+; the last 16 bytes are the 128-bit padding block that is
  # XORed into every AES input, as specified by the published algorithm.
  #
  # The transform is +F(x) = f(x) XOR x+, applied one bit at a time from
  # the most significant bit.  Two addresses that share a prefix of
  # length +n+ therefore always map to addresses that share a prefix of
  # exactly the same length +n+ (the longest-common-prefix relation is
  # preserved).  The transform is bijective and reversible, so
  # {#deanonymize} recovers the original address.
  #
  # Both IPv4 (32-bit) and IPv6 (128-bit) addresses are supported and
  # share the same implementation.  Single addresses and CIDR networks
  # share the same code path: a masked network keeps its prefix length,
  # the result is normalized (host bits cleared), and the address family
  # is preserved.
  #
  # Scoped IPv6 addresses (those carrying a +zone_id+, e.g.
  # +fe80::1%eth0+) are rejected.  A scope identifier is not part of the
  # address bits and cannot be anonymized, so callers must separate the
  # scope before anonymizing and re-attach it to the result if desired.
  #
  # == Security note
  #
  # Prefix preservation is the defining feature of Crypto-PAn but it is
  # also a privacy leak: anyone with the anonymized data can still learn
  # which addresses were colocated in the same network and infer network
  # topology, shared providers, or clustering.  Crypto-PAn must not be
  # described as unlinkable or relationship-hiding anonymization.  Keep
  # the key secret: anyone who holds the key (and the 16-byte padding is
  # part of it) can deanonymize every address.  The key is never exposed
  # through #inspect, error messages, or serialization.
  #
  # == Examples
  #
  #   require 'ipaddr'
  #   require 'ipaddr/crypto_pan'
  #
  #   key = SecureRandom.bytes(32)
  #   anonymizer = IPAddr::CryptoPAn.new(key)
  #
  #   anonymizer.anonymize("192.0.2.5")     #=> #<IPAddr: IPv4:...>
  #   anonymizer.anonymize("2001:db8::/32") #=> #<IPAddr: IPv6:.../32>
  #   anonymizer.deanonymize(anonymizer.anonymize("192.0.2.5")).to_s
  #   #=> "192.0.2.5"
  class CryptoPAn
    # Length of the Crypto-PAn key in bytes (16-byte AES key + 16-byte
    # padding block).
    KEY_SIZE = 32

    # Generic error raised by IPAddr::CryptoPAn.
    class Error < IPAddr::Error; end

    # Raised when the key is not exactly 32 bytes long, is not a String,
    # or is not binary-compatible.
    class InvalidKeyError < Error; end

    # Creates a new CryptoPAn anonymizer from a 32-byte binary +key+.
    #
    # The first 16 bytes form the AES-128 key and the last 16 bytes form
    # the padding block of the published algorithm.
    #
    # Raises InvalidKeyError if +key+ is not a 32-byte String.
    def initialize(key)
      unless key.is_a?(String)
        raise InvalidKeyError, "key must be a #{KEY_SIZE}-byte String"
      end
      unless key.bytesize == KEY_SIZE
        raise InvalidKeyError,
              "key must be #{KEY_SIZE} bytes long (got #{key.bytesize})"
      end

      key = key.b
      @aes_key = key.byteslice(0, 16).freeze
      @padding_integer = key.byteslice(16, 16).unpack1("H*").to_i(16)
      freeze
    end

    # Anonymizes +addr+, preserving its address family, prefix length and
    # longest-common-prefix relations.
    #
    # +addr+ may be an IPAddr or a String understood by IPAddr.new.
    # For a masked network the result keeps the same prefix length and is
    # normalized to the network address (host bits cleared).
    #
    # Raises IPAddr::InvalidAddressError if +addr+ is an IPv6 address
    # carrying a zone identifier; the caller must strip the scope first.
    def anonymize(addr)
      transform(addr, :forward)
    end

    # Recovers the address that {#anonymize} mapped to +addr+.
    #
    # +addr+ may be an IPAddr or a String understood by IPAddr.new.
    # The family and prefix length are preserved and a masked network is
    # normalized to its network address.  Results are only meaningful for
    # addresses anonymized with the same key.
    #
    # Raises IPAddr::InvalidAddressError if +addr+ is an IPv6 address
    # carrying a zone identifier.
    def deanonymize(addr)
      transform(addr, :inverse)
    end

    # Returns a short representation that never contains the key.
    def inspect
      "#<#{self.class.name}>"
    end
    alias to_s inspect

    # Keeps +pp+ from printing instance variables that hold key material.
    def pretty_print(q)
      q.text(inspect)
    end

    private

    def transform(addr, direction)
      ipaddr = coerce(addr)
      family = ipaddr.family
      width = family == Socket::AF_INET ? 32 : 128

      if family == Socket::AF_INET6 && !ipaddr.zone_id.nil?
        raise IPAddr::InvalidAddressError,
              "cannot anonymize a scoped IPv6 address; " \
              "separate the zone identifier first"
      end

      result = transform_bits(ipaddr.to_i, width, direction, new_cipher)

      IPAddr.new(result, family).mask(ipaddr.prefix)
    end

    # Runs the bitwise F(x) = f(x) XOR x transform.
    #
    # In the forward direction the pseudorandom bit for position +i+ is
    # evaluated on the +i+-bit prefix of the original address; during
    # inversion it is evaluated on the already recovered prefix, which
    # restores the original bit.
    def transform_bits(value, width, direction, cipher)
      result = 0
      prefix_value = 0

      width.times do |i|
        result_position = width - 1 - i
        block_position = 127 - i

        prefix_value = value >> (width - i) if direction == :forward

        block = (prefix_value << (128 - i)) ^ @padding_integer
        random_bit = pseudorandom_bit(cipher, block, block_position)
        input_bit = (value >> result_position) & 1

        output_bit = input_bit ^ random_bit
        result |= output_bit << result_position

        if direction == :inverse
          prefix_value = result >> (width - 1 - i)
        end
      end

      result
    end

    # Returns the pseudorandom bit of +f+ at bit position +position+ for
    # the left-aligned 128-bit +block+.
    def pseudorandom_bit(cipher, block, position)
      encrypted = cipher.update(integer_to_block(block))
      (encrypted.unpack1("H*").to_i(16) >> position) & 1
    end

    def new_cipher
      cipher = OpenSSL::Cipher.new("AES-128-ECB")
      cipher.encrypt
      cipher.key = @aes_key
      cipher.padding = 0
      cipher
    end

    # Packs a 128-bit integer into a 16-byte network-ordered block.
    def integer_to_block(integer)
      [integer >> 64, integer & 0xffffffffffffffff].pack("Q>2")
    end

    def coerce(addr)
      case addr
      when IPAddr
        addr
      when String
        IPAddr.new(addr)
      else
        raise IPAddr::AddressFamilyError, "unsupported address"
      end
    end

    # The key is secret, so marshaling a CryptoPAn must not persist it.
    def marshal_dump
      raise TypeError, "cannot marshal #{self.class}"
    end

    def marshal_load(_data)
      raise TypeError, "cannot unmarshal #{self.class}"
    end

    def _dump(_level)
      raise TypeError, "cannot marshal #{self.class}"
    end

    def self._load(_str)
      raise TypeError, "cannot unmarshal #{self}"
    end
  end
end
