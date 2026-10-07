# frozen_string_literal: true
require 'test/unit'
require 'ipaddr/crypto_pan'

class TC_IPAddr_CryptoPAn < Test::Unit::TestCase
  # 32-byte key: bytes 0-15 are the AES-128 key, bytes 16-31 the pad seed.
  KEY = (0..31).map { |i| i }.pack('C*').freeze
  OTHER_KEY = (0..31).map { |i| 0xa5 ^ i }.pack('C*').freeze

  # Public reference vectors for key 00010203...1e1f, computed per the
  # published Crypto-PAn algorithm and cross-checked against an
  # independent implementation that performs AES-128-ECB via the
  # openssl(1) command line tool.
  V4_VECTORS = {
    '0.0.0.0'         => '248.1.16.139',
    '10.0.0.1'        => '243.254.239.117',
    '192.0.2.1'       => '120.1.18.138',
    '203.0.113.99'    => '116.254.161.22',
    '255.255.255.255' => '85.245.250.222',
  }.freeze

  V6_VECTORS = {
    '::'                                 => 'f801:108b:1e2a:fc91:6ff1:11ee:716b:6d6c',
    '2001:db8::1'                        => 'c7ff:e14c:e1d5:036e:900e:ee11:8e94:9292',
    'fe80::1234'                         => '54fe:ef74:e1d5:036e:900e:ee11:8e94:80a4',
    'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' => '55f5:fade:f9bb:9903:3f9a:0c06:8478:2dd1',
    '::ffff:192.0.2.1'                   => 'f801:108b:1e2a:fc91:6ff1:9210:f16b:6f6d',
  }.freeze

  def setup
    @cryptopan = IPAddr::CryptoPAn.new(KEY)
  end

  # Longest common prefix length of two integers of +bits+ bits.
  def lcp(a, b, bits)
    x = a ^ b
    x.zero? ? bits : bits - x.bit_length
  end

  def assert_lcp_preserved(originals, anonymized, bits)
    originals.zip(anonymized).combination(2) do |(a, a_anon), (b, b_anon)|
      assert_equal(lcp(a.to_i, b.to_i, bits), lcp(a_anon.to_i, b_anon.to_i, bits),
                   "shared prefix of #{a} and #{b} not preserved")
    end
  end

  def test_reference_vectors_ipv4
    V4_VECTORS.each do |plain, anonymized|
      assert_equal(IPAddr.new(plain), @cryptopan.deanonymize(anonymized))
      assert_equal(IPAddr.new(anonymized), @cryptopan.anonymize(plain))
    end
  end

  def test_reference_vectors_ipv6
    V6_VECTORS.each do |plain, anonymized|
      assert_equal(IPAddr.new(plain), @cryptopan.deanonymize(anonymized))
      assert_equal(IPAddr.new(anonymized), @cryptopan.anonymize(plain))
    end
  end

  def test_deterministic_with_same_key
    again = IPAddr::CryptoPAn.new(KEY.dup)
    assert_equal(@cryptopan.anonymize('192.0.2.1'), again.anonymize('192.0.2.1'))
    assert_equal(@cryptopan.anonymize('2001:db8::1'), again.anonymize('2001:db8::1'))
  end

  def test_output_differs_with_different_key
    other = IPAddr::CryptoPAn.new(OTHER_KEY)
    (V4_VECTORS.keys + V6_VECTORS.keys).each do |addr|
      assert_not_equal(@cryptopan.anonymize(addr), other.anonymize(addr),
                       "different keys must not map #{addr} to the same address")
    end
  end

  def test_prefix_preservation_and_recovery_ipv4
    originals = %w[
      0.0.0.0 10.0.0.1 10.0.0.2 10.0.1.7 10.1.0.9
      172.16.5.5 192.168.0.1 192.168.0.200 255.255.255.255
    ].map { |s| IPAddr.new(s) }
    anonymized = originals.map { |addr| @cryptopan.anonymize(addr) }

    assert_lcp_preserved(originals, anonymized, 32)
    originals.zip(anonymized) do |plain, anon|
      assert_equal(plain, @cryptopan.deanonymize(anon))
    end
  end

  def test_prefix_preservation_and_recovery_ipv6
    originals = %w[
      :: ::1 2001:db8::1 2001:db8::2 2001:db8:1::1 2001:db9::1
      fe80::1 fe80::2 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
    ].map { |s| IPAddr.new(s) }
    anonymized = originals.map { |addr| @cryptopan.anonymize(addr) }

    assert_lcp_preserved(originals, anonymized, 128)
    originals.zip(anonymized) do |plain, anon|
      assert_equal(plain, @cryptopan.deanonymize(anon))
    end
  end

  def test_accepts_ipaddr_and_string
    assert_equal(@cryptopan.anonymize('192.0.2.1'),
                 @cryptopan.anonymize(IPAddr.new('192.0.2.1')))
  end

  def test_cidr_keeps_prefix_and_normalizes_host_bits
    anon = @cryptopan.anonymize_cidr('192.168.2.130/24')
    assert_equal(24, anon.prefix)
    assert_equal(0, anon.to_i & 0xff)
    assert_equal(IPAddr.new('192.168.2.0/24'), @cryptopan.deanonymize_cidr(anon))

    anon6 = @cryptopan.anonymize_cidr('2001:db8:abcd::1234/48')
    assert_equal(48, anon6.prefix)
    assert_equal(0, anon6.to_i & ((1 << 80) - 1))
    assert_equal(IPAddr.new('2001:db8:abcd::/48'), @cryptopan.deanonymize_cidr(anon6))
  end

  def test_cidr_preserves_shared_prefixes
    a = @cryptopan.anonymize_cidr('10.0.0.0/24')
    b = @cryptopan.anonymize_cidr('10.0.128.0/24')
    c = @cryptopan.anonymize_cidr('10.128.0.0/24')
    # Compare the anonymized 24-bit network prefixes; the zeroed host
    # bits of the masked results would otherwise coincide by accident.
    assert_equal(16, lcp(a.to_i >> 8, b.to_i >> 8, 24))
    assert_equal(8, lcp(a.to_i >> 8, c.to_i >> 8, 24))
  end

  def test_zone_id_rejected
    zoned = IPAddr.new('fe80::1%eth0')
    assert_raise(IPAddr::CryptoPAn::ZoneError) { @cryptopan.anonymize(zoned) }
    assert_raise(IPAddr::CryptoPAn::ZoneError) { @cryptopan.anonymize('fe80::1%eth0') }
    assert_raise(IPAddr::CryptoPAn::ZoneError) { @cryptopan.anonymize_cidr('fe80::1%eth0') }
    # The caller separates the scope first; the bare address anonymizes fine.
    bare = IPAddr.new('fe80::1')
    assert_equal(bare, @cryptopan.deanonymize(@cryptopan.anonymize(bare)))
  end

  def test_address_families_are_independent_namespaces
    v4 = @cryptopan.anonymize('192.0.2.1')
    mapped = @cryptopan.anonymize('::ffff:192.0.2.1')
    assert(v4.ipv4?)
    assert(mapped.ipv6?)
    assert_not_equal(v4.to_i, mapped.to_i)
    assert_equal(IPAddr.new('::ffff:192.0.2.1'), @cryptopan.deanonymize(mapped))
    # Opt-in IPv4 semantics for mapped addresses via IPAddr#native.
    native = IPAddr.new('::ffff:192.0.2.1').native
    assert_equal(v4, @cryptopan.anonymize(native))
  end

  def test_key_contract
    assert_raise(IPAddr::CryptoPAn::KeyError) { IPAddr::CryptoPAn.new('too short') }
    assert_raise(IPAddr::CryptoPAn::KeyError) { IPAddr::CryptoPAn.new('k' * 31) }
    assert_raise(IPAddr::CryptoPAn::KeyError) { IPAddr::CryptoPAn.new('k' * 33) }
    assert_raise(IPAddr::CryptoPAn::KeyError) { IPAddr::CryptoPAn.new(nil) }
    assert_raise(IPAddr::CryptoPAn::KeyError) { IPAddr::CryptoPAn.new(32) }
  end

  def test_key_not_leaked
    key_hex = KEY.unpack1('H*')

    assert_not_include(@cryptopan.inspect, KEY)
    assert_not_include(@cryptopan.inspect, key_hex)

    error = assert_raise(IPAddr::CryptoPAn::KeyError) { IPAddr::CryptoPAn.new(KEY[0, 16]) }
    assert_not_include(error.message, KEY)
    assert_not_include(error.message, key_hex)

    zone_error = assert_raise(IPAddr::CryptoPAn::ZoneError) { @cryptopan.anonymize('fe80::1%eth0') }
    assert_not_include(zone_error.message, KEY)
    assert_not_include(zone_error.message, key_hex)

    assert_raise(TypeError) { Marshal.dump(@cryptopan) }
  end

  def test_invalid_address
    assert_raise(IPAddr::InvalidAddressError) { @cryptopan.anonymize('not an address') }
  end
end
