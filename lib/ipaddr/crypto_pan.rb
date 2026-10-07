# frozen_string_literal: true
#
# ipaddr/crypto_pan.rb - Crypto-PAn prefix-preserving IP address anonymization
#
# This file is part of the ipaddr library and distributed under the same
# terms as Ruby.
#
# Implements the Crypto-PAn algorithm published in:
#
#   Jun Xu, Jinliang Fan, Mostafa H. Ammar, Sue B. Moon,
#   "Prefix-Preserving IP Address Anonymization: Measurement-based
#   Security Evaluation and a New Cryptography-based Scheme",
#   ICNP 2002.  Reference implementation: CryptoPAn-1.0.
#
# Algorithm summary (generalized here to both 32-bit IPv4 and 128-bit
# IPv6 addresses):
#
#   * The key is 32 bytes: the first 16 bytes are an AES-128 key K, the
#     last 16 bytes are a pad seed P.
#   * pad = AES_K(P), a 128-bit block used as a one-time pad.
#   * For each bit position i (0-based, most significant first) of the
#     N-bit address a:
#       - build a 128-bit block from the first i bits of the ORIGINAL
#         address a, most-significant-bit aligned, zero padded;
#       - f_i = the most significant bit of AES_K(block);
#       - output bit b'_i = a_i XOR pad_i XOR f_i.
#   * Because f_i depends only on the first i-1 original bits, the
#     transform is an involution-style bijection that is fully
#     invertible bit by bit, and two addresses sharing a k-bit prefix
#     map to addresses sharing a k-bit prefix.

require 'openssl'
require 'ipaddr'

class IPAddr
  # IPAddr::CryptoPAn anonymizes IP addresses with the Crypto-PAn
  # prefix-preserving, cryptography-based scheme.
  #
  # The same key always maps the same address to the same anonymized
  # address (deterministic), the mapping is a bijection and can be
  # reversed with the same key (invertible), and addresses that share a
  # common prefix keep a common prefix of the same length after
  # anonymization (prefix-preserving).
  #
  # === Contract
  #
  # Key::
  #   Exactly 32 bytes: bytes 0-15 are the AES-128 key, bytes 16-31 are
  #   the pad seed.  The key is never exposed through #inspect, error
  #   messages, or serialization (serialization is refused outright).
  #
  # Address family::
  #   IPv4 addresses are anonymized as 32-bit values and IPv6 addresses
  #   as 128-bit values; the two families form independent namespaces,
  #   so prefix relationships are only preserved within one family.
  #   IPv4-mapped/compatible IPv6 addresses are treated as IPv6; call
  #   IPAddr#native first if you want them anonymized as IPv4.
  #
  # Prefix length::
  #   #anonymize and #deanonymize transform the bare address and return
  #   a full-length address (/32 or /128).  #anonymize_cidr and
  #   #deanonymize_cidr keep the network prefix length of the input and
  #   normalize (zero) the host bits of the result.
  #
  # Zone (scope) id::
  #   Addresses carrying an IPv6 zone id (e.g. "fe80::1%eth0") are
  #   rejected with IPAddr::CryptoPAn::Error; split the scope zone off
  #   before anonymizing and re-attach it afterwards if needed.
  #
  # === Security note
  #
  # Prefix preservation is a property of the algorithm, not a privacy
  # guarantee: by construction it reveals which anonymized addresses
  # share prefixes and for how long, so this tool must NOT be presented
  # as unlinkable anonymization.  Anyone holding the key can reverse
  # every mapping; keep the key secret and rotate it when unlinkability
  # across data sets is required.
  #
  # === Example
  #
  #   require 'ipaddr/crypto_pan'
  #
  #   key = Random.bytes(32)           # store this somewhere safe
  #   cryptopan = IPAddr::CryptoPAn.new(key)
  #
  #   anon = cryptopan.anonymize('192.0.2.1')
  #   cryptopan.deanonymize(anon)      #=> #<IPAddr: IPv4:192.0.2.1/255.255.255.255>
  #
  #   cryptopan.anonymize_cidr('192.0.2.128/25')  # keeps the /25 mask
  class CryptoPAn
    # Length of the key in bytes: 16 bytes of AES-128 key material
    # followed by a 16-byte pad seed, as specified by Crypto-PAn.
    KEY_LENGTH = 32

    # Generic error raised by IPAddr::CryptoPAn.  Messages never contain
    # key material.
    class Error < StandardError; end

    # Raised when the key does not satisfy the 32-byte contract.
    class KeyError < ArgumentError; end

    # Raised when an address carries an IPv6 zone (scope) id.
    class ZoneError < Error; end

    AES_KEY_LENGTH = 16   # :nodoc:
    BLOCK_BITS = 128      # :nodoc:
    IPV4_BITS = 32        # :nodoc:
    IPV6_BITS = 128       # :nodoc:
    UINT64_MASK = 0xffffffffffffffff  # :nodoc:

    # Creates an anonymizer from a 32-byte key String.  The key is used
    # internally to derive the AES key schedule and the pad, and is not
    # retained as a whole afterwards.
    def initialize(key)
      unless key.is_a?(String) && key.bytesize == KEY_LENGTH
        raise KeyError,
              "Crypto-PAn key must be a #{KEY_LENGTH}-byte String " \
              "(16-byte AES-128 key followed by a 16-byte pad seed)"
      end
      @aes_key = key.byteslice(0, AES_KEY_LENGTH).b.freeze
      @pad = block_to_int(aes_encrypt(key.byteslice(AES_KEY_LENGTH, AES_KEY_LENGTH)))
    end

    # Returns the anonymized form of +address+ (a String or an IPAddr)
    # as a full-length IPAddr (/32 for IPv4, /128 for IPv6).
    def anonymize(address)
      addr, bits, family = coerce(address)
      IPAddr.new(anonymize_int(addr.to_i, bits), family)
    end

    # Returns the original address for an address produced by
    # #anonymize with the same key.
    def deanonymize(address)
      addr, bits, family = coerce(address)
      IPAddr.new(deanonymize_int(addr.to_i, bits), family)
    end

    # Anonymizes the network address of +address+ (a String or IPAddr
    # with a prefix, e.g. "192.0.2.128/25") and returns an IPAddr with
    # the same prefix length and zeroed host bits.
    def anonymize_cidr(address)
      addr, bits, family = coerce(address)
      IPAddr.new(anonymize_int(addr.to_i, bits), family).mask(addr.prefix)
    end

    # Reverses #anonymize_cidr: deanonymizes the network address and
    # returns an IPAddr with the same prefix length and zeroed host
    # bits.
    def deanonymize_cidr(address)
      addr, bits, family = coerce(address)
      IPAddr.new(deanonymize_int(addr.to_i, bits), family).mask(addr.prefix)
    end

    # Returns a representation that never includes key material.
    def inspect
      "#<#{self.class.name} key=[redacted]>"
    end

    # IPAddr::CryptoPAn holds secret key material and refuses
    # serialization so that the key cannot leak into dumps.
    def marshal_dump
      raise TypeError, "IPAddr::CryptoPAn holds secret key material and cannot be serialized"
    end

    private

    # Normalizes the input into [IPAddr, bit width, address family] and
    # enforces the zone-id contract.
    def coerce(address)
      addr = address.is_a?(IPAddr) ? address : IPAddr.new(address.to_s)
      if addr.ipv4?
        [addr, IPV4_BITS, Socket::AF_INET]
      else
        unless addr.zone_id.nil?
          raise ZoneError,
                "address has a zone id #{addr.zone_id}; split the scope zone off before anonymizing"
        end
        [addr, IPV6_BITS, Socket::AF_INET6]
      end
    end

    # Crypto-PAn forward transform on the +bits+-bit integer +value+.
    def anonymize_int(value, bits)
      result = 0
      pos = 0
      while pos < bits
        block = prefix_block(value, bits, pos)
        flip = pad_bit(pos) ^ cipher_bit(block)
        result |= (bit_at(value, bits, pos) ^ flip) << (bits - 1 - pos)
        pos += 1
      end
      result
    end

    # Crypto-PAn inverse transform: identical to the forward transform
    # except the AES input is rebuilt from the already recovered
    # original bits.
    def deanonymize_int(value, bits)
      result = 0
      pos = 0
      while pos < bits
        block = prefix_block(result, bits, pos)
        flip = pad_bit(pos) ^ cipher_bit(block)
        result |= (bit_at(value, bits, pos) ^ flip) << (bits - 1 - pos)
        pos += 1
      end
      result
    end

    # 128-bit AES input block: the first +pos+ bits of the +bits+-bit
    # value, MSB-aligned, zero padded.
    def prefix_block(value, bits, pos)
      return 0 if pos.zero?

      (value >> (bits - pos)) << (BLOCK_BITS - pos)
    end

    def bit_at(value, bits, pos)
      (value >> (bits - 1 - pos)) & 1
    end

    def pad_bit(pos)
      (@pad >> (BLOCK_BITS - 1 - pos)) & 1
    end

    # Most significant bit of AES_K(block).
    def cipher_bit(block)
      block_to_int(aes_encrypt(int_to_block(block))) >> (BLOCK_BITS - 1)
    end

    def aes_encrypt(data)
      cipher = @cipher ||= begin
        c = OpenSSL::Cipher.new('aes-128-ecb')
        c.encrypt
        c.key = @aes_key
        c.padding = 0
        c
      end
      cipher.reset
      cipher.update(data) + cipher.final
    end

    def int_to_block(int)
      [int >> 64, int & UINT64_MASK].pack('Q>2')
    end

    def block_to_int(block)
      hi, lo = block.unpack('Q>2')
      (hi << 64) | lo
    end
  end
end
