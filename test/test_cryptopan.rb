# frozen_string_literal: true
require 'test/unit'
require 'ipaddr'
require 'ipaddr/crypto_pan'
require 'pp'

class TC_CryptoPAn < Test::Unit::TestCase
  KEY = ["00112233445566778899aabbccddeeff" \
         "000102030405060708090a0b0c0d0e0f"].pack("H*").freeze

  # Public reference vectors for F(x) = f(x) XOR x with KEY above.
  IPV4_VECTORS = {
    "0.0.0.0"         => "39.159.183.74",
    "127.0.0.1"       => "78.169.18.48",
    "192.168.1.1"     => "208.23.87.35",
    "10.0.0.1"        => "44.58.126.168",
    "1.2.3.4"         => "38.93.85.28",
    "255.255.255.255" => "246.77.4.11",
  }.freeze

  IPV6_VECTORS = {
    "::"                          => "279f:b74a:7572:135e:8f9b:8ef6:d1ee:e003",
    "::1"                         => "279f:b74a:7572:135e:8f9b:8ef6:d1ee:e002",
    "2001:db8::1"                 => "dca:fbd7:c523:eec4:9111:eca3:65ce:85d1",
    "fe80::1"                     => "f706:8bab:511d:163e:23b:eb:66e0:d898",
    "2001:db8:85a3::8a2e:370:7334" => "dca:fbd7:d41:b34b:8117:a973:5ee:eb96",
  }.freeze

  def setup
    @cp = IPAddr::CryptoPAn.new(KEY)
  end

  def test_reference_vectors_ipv4
    IPV4_VECTORS.each do |input, expected|
      assert_equal(expected, @cp.anonymize(input).to_s, input)
    end
  end

  def test_reference_vectors_ipv6
    IPV6_VECTORS.each do |input, expected|
      assert_equal(expected, @cp.anonymize(input).to_s, input)
    end
  end

  def test_deterministic
    vector = IPV4_VECTORS.keys + IPV6_VECTORS.keys
    other = IPAddr::CryptoPAn.new(KEY.dup)
    vector.each do |address|
      assert_equal(@cp.anonymize(address).to_s,
                   @cp.anonymize(IPAddr.new(address)).to_s,
                   address)
      assert_equal(@cp.anonymize(address).to_s,
                   other.anonymize(address).to_s,
                   address)
    end
  end

  def test_roundtrip
    (IPV4_VECTORS.keys + IPV6_VECTORS.keys).each do |address|
      anonymized = @cp.anonymize(address)
      recovered = @cp.deanonymize(anonymized)
      assert_equal(address, recovered.to_s, address)
    end
  end

  def test_preserves_family
    assert_equal(Socket::AF_INET, @cp.anonymize("192.0.2.1").family)
    assert_equal(Socket::AF_INET6, @cp.anonymize("2001:db8::1").family)
    assert_equal(Socket::AF_INET,
                 @cp.deanonymize(@cp.anonymize("192.0.2.1")).family)
    assert_equal(Socket::AF_INET6,
                 @cp.deanonymize(@cp.anonymize("2001:db8::1")).family)
  end

  def test_longest_common_prefix_is_preserved
    [32, 128].each do |width|
      addresses = (width == 32 ? IPV4_VECTORS : IPV6_VECTORS).keys
      addresses = addresses.map { |address| IPAddr.new(address) }
      addresses.permutation(2) do |a, b|
        expected = longest_common_prefix(a.to_i, b.to_i, width)
        actual = longest_common_prefix(@cp.anonymize(a).to_i,
                                       @cp.anonymize(b).to_i, width)
        assert_equal(expected, actual,
                     "LCP(#{a}, #{b}) must be preserved")
      end
    end
  end

  def test_cidr_keeps_prefix_and_normalizes_host_bits
    {
      "192.168.0.1/24"   => ["208.23.86.0/24",   24],
      "10.1.2.3/8"       => ["44.0.0.0/8",       8],
      "2001:db8::1/32"   => ["dca:fbd7::/32",    32],
      "2001:db8::dead/48" => ["dca:fbd7:c523::/48", 48],
      "192.0.2.5/32"     => [@cp.anonymize("192.0.2.5").cidr, 32],
      "2001:db8::1/128"  => [@cp.anonymize("2001:db8::1").cidr, 128],
    }.each do |input, (expected_cidr, expected_prefix)|
      result = @cp.anonymize(IPAddr.new(input))
      assert_equal(expected_cidr, result.cidr, input)
      assert_equal(expected_prefix, result.prefix, input)
    end
  end

  def test_cidr_network_prefix_matches_member_anonymization
    network = "192.168.1.128/24"
    anonymized_network = @cp.anonymize(network)
    anonymized_member = @cp.anonymize("192.168.1.1")
    assert_equal(anonymized_network.to_s,
                 anonymized_member.mask(24).to_s)

    recovered = @cp.deanonymize(anonymized_network)
    assert_equal("192.168.1.0/24", recovered.cidr)
  end

  def test_scoped_ipv6_is_rejected
    error = assert_raise(IPAddr::InvalidAddressError) do
      @cp.anonymize("fe80::1%eth0")
    end
    assert_match(/scope/, error.message)

    assert_raise(IPAddr::InvalidAddressError) do
      @cp.deanonymize("fe80::1%eth0")
    end
  end

  def test_invalid_key
    assert_raise(IPAddr::CryptoPAn::InvalidKeyError) do
      IPAddr::CryptoPAn.new("a" * 31)
    end
    assert_raise(IPAddr::CryptoPAn::InvalidKeyError) do
      IPAddr::CryptoPAn.new("a" * 33)
    end
    assert_raise(IPAddr::CryptoPAn::InvalidKeyError) do
      IPAddr::CryptoPAn.new(nil)
    end
    assert_raise(IPAddr::CryptoPAn::InvalidKeyError) do
      IPAddr::CryptoPAn.new(0)
    end
    assert_kind_of(IPAddr::Error,
                   IPAddr::CryptoPAn::InvalidKeyError.new)
  end

  def test_unsupported_input
    assert_raise(IPAddr::AddressFamilyError) do
      @cp.anonymize(123)
    end
  end

  def test_different_keys_produce_different_outputs
    other_key = ("\xff" * 32).b
    other = IPAddr::CryptoPAn.new(other_key)
    (IPV4_VECTORS.keys + IPV6_VECTORS.keys).each do |address|
      assert_not_equal(@cp.anonymize(address).to_s,
                       other.anonymize(address).to_s,
                       address)
      assert_equal(address,
                   other.deanonymize(other.anonymize(address)).to_s,
                   address)
    end
  end

  def test_key_is_not_exposed
    assert_equal("#<IPAddr::CryptoPAn>", @cp.inspect)
    assert_equal(@cp.inspect, @cp.to_s)
    assert_equal(@cp.inspect, PP.pp(@cp, +"").chomp)

    [KEY, KEY[0, 16], KEY[16, 16]].each do |secret|
      refute_includes(@cp.inspect, secret.b)
    end

    error = assert_raise(IPAddr::CryptoPAn::InvalidKeyError) do
      IPAddr::CryptoPAn.new(KEY[0, 10])
    end
    refute_includes(error.message, KEY[0, 10])

    assert_raise(TypeError) { Marshal.dump(@cp) }
  end

  private

  def longest_common_prefix(a, b, width)
    i = 0
    while i < width && ((a >> (width - 1 - i)) & 1) == ((b >> (width - 1 - i)) & 1)
      i += 1
    end
    i
  end
end
