# frozen_string_literal: true
require 'test/unit'
require 'ipaddr'

class TC_IPAddr < Test::Unit::TestCase
  def test_s_new
    [
      ["3FFE:505:ffff::/48"],
      ["0:0:0:1::"],
      ["2001:200:300::/48"],
      ["2001:200:300::192.168.1.2/48"],
      ["1:2:3:4:5:6:7::"],
      ["::2:3:4:5:6:7:8"],
    ].each { |args|
      assert_nothing_raised {
        IPAddr.new(*args)
      }
    }

    a = IPAddr.new
    assert_equal("::", a.to_s)
    assert_equal("0000:0000:0000:0000:0000:0000:0000:0000", a.to_string)
    assert_equal("::/128", a.cidr)
    assert_equal(Socket::AF_INET6, a.family)
    assert_equal(128, a.prefix)

    a = IPAddr.new("0123:4567:89ab:cdef:0ABC:DEF0:1234:5678")
    assert_equal("123:4567:89ab:cdef:abc:def0:1234:5678", a.to_s)
    assert_equal("0123:4567:89ab:cdef:0abc:def0:1234:5678", a.to_string)
    assert_equal("123:4567:89ab:cdef:abc:def0:1234:5678/128", a.cidr)
    assert_equal(Socket::AF_INET6, a.family)
    assert_equal(128, a.prefix)

    a = IPAddr.new("3ffe:505:2::/48")
    assert_equal("3ffe:505:2::", a.to_s)
    assert_equal("3ffe:0505:0002:0000:0000:0000:0000:0000", a.to_string)
    assert_equal("3ffe:505:2::/48", a.cidr)
    assert_equal(Socket::AF_INET6, a.family)
    assert_equal(false, a.ipv4?)
    assert_equal(true, a.ipv6?)
    assert_equal("#<IPAddr: IPv6:3ffe:0505:0002:0000:0000:0000:0000:0000/ffff:ffff:ffff:0000:0000:0000:0000:0000>", a.inspect)
    assert_equal(48, a.prefix)

    a = IPAddr.new("3ffe:505:2::/ffff:ffff:ffff::")
    assert_equal("3ffe:505:2::", a.to_s)
    assert_equal("3ffe:0505:0002:0000:0000:0000:0000:0000", a.to_string)
    assert_equal("3ffe:505:2::/48", a.cidr)
    assert_equal(Socket::AF_INET6, a.family)
    assert_equal(48, a.prefix)
    assert_nil(a.zone_id)

    a = IPAddr.new("fe80::1%ab0")
    assert_equal("fe80::1%ab0", a.to_s)
    assert_equal("fe80:0000:0000:0000:0000:0000:0000:0001%ab0", a.to_string)
    assert_equal(Socket::AF_INET6, a.family)
    assert_equal(false, a.ipv4?)
    assert_equal(true, a.ipv6?)
    assert_equal("#<IPAddr: IPv6:fe80:0000:0000:0000:0000:0000:0000:0001%ab0/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff>", a.inspect)
    assert_equal(128, a.prefix)
    assert_equal('%ab0', a.zone_id)

    a = IPAddr.new("0.0.0.0")
    assert_equal("0.0.0.0", a.to_s)
    assert_equal("0.0.0.0", a.to_string)
    assert_equal("0.0.0.0/32", a.cidr)
    assert_equal(Socket::AF_INET, a.family)
    assert_equal(32, a.prefix)

    a = IPAddr.new("192.168.1.2")
    assert_equal("192.168.1.2", a.to_s)
    assert_equal("192.168.1.2", a.to_string)
    assert_equal("192.168.1.2/32", a.cidr)
    assert_equal(Socket::AF_INET, a.family)
    assert_equal(true, a.ipv4?)
    assert_equal(false, a.ipv6?)
    assert_equal(32, a.prefix)

    a = IPAddr.new("192.168.1.2/26")
    assert_equal("192.168.1.0", a.to_s)
    assert_equal("192.168.1.0", a.to_string)
    assert_equal("192.168.1.0/26", a.cidr)
    assert_equal(Socket::AF_INET, a.family)
    assert_equal("#<IPAddr: IPv4:192.168.1.0/255.255.255.192>", a.inspect)
    assert_equal(26, a.prefix)

    a = IPAddr.new("192.168.1.2/255.255.255.0")
    assert_equal("192.168.1.0", a.to_s)
    assert_equal("192.168.1.0", a.to_string)
    assert_equal("192.168.1.0/24", a.cidr)
    assert_equal(Socket::AF_INET, a.family)
    assert_equal(24, a.prefix)

    (0..32).each do |prefix|
      assert_equal(prefix, IPAddr.new("10.20.30.40/#{prefix}").prefix)
    end
    (0..128).each do |prefix|
      assert_equal(prefix, IPAddr.new("1:2:3:4:5:6:7:8/#{prefix}").prefix)
    end

    assert_equal("0:0:0:1::", IPAddr.new("0:0:0:1::").to_s)
    assert_equal("2001:200:300::", IPAddr.new("2001:200:300::/48").to_s)

    assert_equal("2001:200:300::", IPAddr.new("[2001:200:300::]/48").to_s)
    assert_equal("1:2:3:4:5:6:7:0", IPAddr.new("1:2:3:4:5:6:7::").to_s)
    assert_equal("0:2:3:4:5:6:7:8", IPAddr.new("::2:3:4:5:6:7:8").to_s)

    assert_raise(IPAddr::InvalidAddressError) { IPAddr.new("192.168.0.256") }
    assert_raise(IPAddr::InvalidAddressError) { IPAddr.new("192.168.0.011") }
    assert_raise(IPAddr::InvalidAddressError) { IPAddr.new("fe80::1%") }
    assert_raise(IPAddr::InvalidAddressError) { IPAddr.new("fe80::1%]") }
    assert_raise(IPAddr::InvalidAddressError) { IPAddr.new("[192.168.1.2]/120") }
    assert_raise(IPAddr::InvalidAddressError) { IPAddr.new("[2001:200:300::]\nINVALID") }
    assert_raise(IPAddr::InvalidAddressError) { IPAddr.new("192.168.0.1/32\nINVALID") }
    assert_raise(IPAddr::InvalidAddressError) { IPAddr.new("192.168.0.1/32/20") }
    assert_raise(IPAddr::InvalidPrefixError) { IPAddr.new("192.168.0.1/032") }
    assert_raise(IPAddr::InvalidPrefixError) { IPAddr.new("::1/0128") }
    assert_raise(IPAddr::InvalidPrefixError) { IPAddr.new("::1/255.255.255.0") }
    assert_raise(IPAddr::InvalidPrefixError) { IPAddr.new("::1/129") }
    assert_raise(IPAddr::InvalidPrefixError) { IPAddr.new("192.168.0.1/33") }
    assert_raise(IPAddr::InvalidPrefixError) { IPAddr.new("192.168.0.1/255.255.255.1") }
    assert_raise(IPAddr::AddressFamilyError) { IPAddr.new(1) }
    assert_raise(IPAddr::AddressFamilyError) { IPAddr.new("::ffff:192.168.1.2/120", Socket::AF_INET) }
  end

  def test_s_new_ntoh
    addr = ''
    IPAddr.new("1234:5678:9abc:def0:1234:5678:9abc:def0").hton.each_byte { |c|
      addr += sprintf("%02x", c)
    }
    assert_equal("123456789abcdef0123456789abcdef0", addr)
    addr = ''
    IPAddr.new("123.45.67.89").hton.each_byte { |c|
      addr += sprintf("%02x", c)
    }
    assert_equal(sprintf("%02x%02x%02x%02x", 123, 45, 67, 89), addr)
    a = IPAddr.new("3ffe:505:2::")
    assert_equal("3ffe:505:2::", IPAddr.new_ntoh(a.hton).to_s)
    a = IPAddr.new("192.168.2.1")
    assert_equal("192.168.2.1", IPAddr.new_ntoh(a.hton).to_s)
  end

  def test_ntop
    # IPv4
    assert_equal("192.168.1.1", IPAddr.ntop("\xC0\xA8\x01\x01".b))
    assert_equal("10.231.140.171", IPAddr.ntop("\x0A\xE7\x8C\xAB".b))
    # IPv6
    assert_equal("0000:0000:0000:0000:0000:0000:0000:0001",
                 IPAddr.ntop("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01".b))
    assert_equal("fe80:0000:0000:0000:f09f:9985:f09f:9986",
                 IPAddr.ntop("\xFE\x80\x00\x00\x00\x00\x00\x00\xF0\x9F\x99\x85\xF0\x9F\x99\x86".b))

    # Invalid parameters
    ## wrong length
    assert_raise(IPAddr::AddressFamilyError) {
      IPAddr.ntop("192.168.1.1".b)
    }
    assert_raise(IPAddr::AddressFamilyError) {
      IPAddr.ntop("\xC0\xA8\x01\xFF1".b)
    }
    ## UTF-8
    assert_raise(IPAddr::InvalidAddressError) {
      IPAddr.ntop("192.168.1.1")
    }
    assert_raise(IPAddr::InvalidAddressError) {
      IPAddr.ntop("\x0A\x0A\x0A\x0A")
    }
    assert_raise(IPAddr::InvalidAddressError) {
      IPAddr.ntop("\x0A\xE7\x8C\xAB")
    }
    assert_raise(IPAddr::InvalidAddressError) {
      IPAddr.ntop("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
    }
    assert_raise(IPAddr::InvalidAddressError) {
      IPAddr.ntop("\xFE\x80\x00\x00\x00\x00\x00\x00\xF0\x9F\x99\x85\xF0\x9F\x99\x86")
    }
  end

  def test_ipv4_compat
    a = IPAddr.new("::192.168.1.2")
    assert_equal("::192.168.1.2", a.to_s)
    assert_equal("0000:0000:0000:0000:0000:0000:c0a8:0102", a.to_string)
    assert_equal(Socket::AF_INET6, a.family)
    assert_warning(/obsolete/) {
      assert_predicate(a, :ipv4_compat?)
    }
    b = a.native
    assert_equal("192.168.1.2", b.to_s)
    assert_equal(Socket::AF_INET, b.family)
    assert_warning(/obsolete/) {
      assert_not_predicate(b, :ipv4_compat?)
    }

    a = IPAddr.new("192.168.1.2")
    assert_warning(/obsolete/) {
      b = a.ipv4_compat
    }
    assert_equal("::192.168.1.2", b.to_s)
    assert_equal(Socket::AF_INET6, b.family)
    assert_equal(128, b.prefix)

    a = IPAddr.new("192.168.0.0/16")
    assert_warning(/obsolete/) {
      b = a.ipv4_compat
    }
    assert_equal("::192.168.0.0", b.to_s)
    assert_equal(Socket::AF_INET6, b.family)
    assert_equal(112, b.prefix)
  end

  def test_ipv4_compat_with_error_message
    e = assert_raise(IPAddr::InvalidAddressError) do
      assert_warning(/obsolete/) {
        IPAddr.new('2001:db8::').ipv4_compat
      }
    end
    assert_equal('not an IPv4 address: 2001:db8::', e.message)
  end

  def test_ipv4_mapped
    a = IPAddr.new("::ffff:192.168.1.2")
    assert_equal("::ffff:192.168.1.2", a.to_s)
    assert_equal("0000:0000:0000:0000:0000:ffff:c0a8:0102", a.to_string)
    assert_equal(Socket::AF_INET6, a.family)
    assert_equal(true, a.ipv4_mapped?)
    b = a.native
    assert_equal("192.168.1.2", b.to_s)
    assert_equal(Socket::AF_INET, b.family)
    assert_equal(false, b.ipv4_mapped?)

    a = IPAddr.new("192.168.1.2")
    b = a.ipv4_mapped
    assert_equal("::ffff:192.168.1.2", b.to_s)
    assert_equal(Socket::AF_INET6, b.family)
  end

  def test_ipv4_mapped_with_error_message
    e = assert_raise(IPAddr::InvalidAddressError) do
      IPAddr.new('2001:db8::').ipv4_mapped
    end
    assert_equal('not an IPv4 address: 2001:db8::', e.message)
  end

  def test_reverse
    assert_equal("f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.5.0.5.0.e.f.f.3.ip6.arpa", IPAddr.new("3ffe:505:2::f").reverse)
    assert_equal("1.2.168.192.in-addr.arpa", IPAddr.new("192.168.2.1").reverse)
  end

  def test_ip6_arpa
    assert_equal("f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.5.0.5.0.e.f.f.3.ip6.arpa", IPAddr.new("3ffe:505:2::f").ip6_arpa)
    e = assert_raise(IPAddr::InvalidAddressError) {
      IPAddr.new("192.168.2.1").ip6_arpa
    }
    assert_equal('not an IPv6 address: 192.168.2.1', e.message)
  end

  def test_ip6_int
    assert_equal("f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.5.0.5.0.e.f.f.3.ip6.int", IPAddr.new("3ffe:505:2::f").ip6_int)
    e = assert_raise(IPAddr::InvalidAddressError) {
      IPAddr.new("192.168.2.1").ip6_int
    }
    assert_equal('not an IPv6 address: 192.168.2.1', e.message)
  end

  def test_prefix_writer
    a = IPAddr.new("192.168.1.2")
    ["1", "255.255.255.0", "ffff:ffff:ffff:ffff::", nil, 1.0, -1, 33].each { |x|
      assert_raise(IPAddr::InvalidPrefixError) { a.prefix = x }
    }
    a = IPAddr.new("1:2:3:4:5:6:7:8")
    ["1", "255.255.255.0", "ffff:ffff:ffff:ffff::", nil, 1.0, -1, 129].each { |x|
      assert_raise(IPAddr::InvalidPrefixError) { a.prefix = x }
    }

    a = IPAddr.new("192.168.1.2")
    a.prefix = 26
    assert_equal(26, a.prefix)
    assert_equal("192.168.1.0", a.to_s)

    a = IPAddr.new("1:2:3:4:5:6:7:8")
    a.prefix = 52
    assert_equal(52, a.prefix)
    assert_equal("1:2:3::", a.to_s)
  end

  def test_to_s
    assert_equal("3ffe:0505:0002:0000:0000:0000:0000:0001", IPAddr.new("3ffe:505:2::1").to_string)
    assert_equal("3ffe:505:2::1", IPAddr.new("3ffe:505:2::1").to_s)
  end

  def test_as_json
    assert_equal("192.168.1.2", IPAddr.new("192.168.1.2").as_json)
    assert_equal("192.168.1.0/24", IPAddr.new("192.168.1.2/24").as_json)
    assert_equal("2001:200:300::1", IPAddr.new("2001:200:300::1").as_json)
    assert_equal("2001:200:300::/48", IPAddr.new("2001:200:300::/48").as_json)
  end

  def test_to_json
    assert_equal("\"192.168.1.2\"", IPAddr.new("192.168.1.2").to_json)
    assert_equal("\"192.168.1.0/24\"", IPAddr.new("192.168.1.2/24").to_json)
    assert_equal("\"2001:200:300::1\"", IPAddr.new("2001:200:300::1").to_json)
    assert_equal("\"2001:200:300::/48\"", IPAddr.new("2001:200:300::/48").to_json)
  end

  def test_netmask
    a = IPAddr.new("192.168.1.2/8")
    assert_equal(a.netmask, "255.0.0.0")

    a = IPAddr.new("192.168.1.2/16")
    assert_equal(a.netmask, "255.255.0.0")

    a = IPAddr.new("192.168.1.2/24")
    assert_equal(a.netmask, "255.255.255.0")
  end

  def test_wildcard_mask
    a = IPAddr.new("192.168.1.2/1")
    assert_equal(a.wildcard_mask, "127.255.255.255")

    a = IPAddr.new("192.168.1.2/8")
    assert_equal(a.wildcard_mask, "0.255.255.255")

    a = IPAddr.new("192.168.1.2/16")
    assert_equal(a.wildcard_mask, "0.0.255.255")

    a = IPAddr.new("192.168.1.2/24")
    assert_equal(a.wildcard_mask, "0.0.0.255")

    a = IPAddr.new("192.168.1.2/32")
    assert_equal(a.wildcard_mask, "0.0.0.0")

    a = IPAddr.new("3ffe:505:2::/48")
    assert_equal(a.wildcard_mask, "0000:0000:0000:ffff:ffff:ffff:ffff:ffff")

    a = IPAddr.new("3ffe:505:2::/128")
    assert_equal(a.wildcard_mask, "0000:0000:0000:0000:0000:0000:0000:0000")
  end

  def test_zone_id
    a = IPAddr.new("192.168.1.2")
    assert_raise(IPAddr::InvalidAddressError) { a.zone_id = '%ab0' }
    assert_raise(IPAddr::InvalidAddressError) { a.zone_id }

    a = IPAddr.new("1:2:3:4:5:6:7:8")
    a.zone_id = '%ab0'
    assert_equal('%ab0', a.zone_id)
    assert_equal("1:2:3:4:5:6:7:8%ab0", a.to_s)
    assert_raise(IPAddr::InvalidAddressError) { a.zone_id = '%' }
  end

  def test_to_range
    a1 = IPAddr.new("127.0.0.1")
    range = a1..a1
    assert_equal(range, a1.to_range)
    assert_equal(range, a1.freeze.to_range)

    a2 = IPAddr.new("192.168.0.1/16")
    range = IPAddr.new("192.168.0.0")..IPAddr.new("192.168.255.255")
    assert_equal(range, a2.to_range)
    assert_equal(range, a2.freeze.to_range)

    a3 = IPAddr.new("3ffe:505:2::1")
    range = a3..a3
    assert_equal(range, a3.to_range)
    assert_equal(range, a3.freeze.to_range)

    a4 = IPAddr.new("::ffff/127")
    range = IPAddr.new("::fffe")..IPAddr.new("::ffff")
    assert_equal(range, a4.to_range)
    assert_equal(range, a4.freeze.to_range)
  end
end

class TC_Operator < Test::Unit::TestCase

  IN6MASK32  = "ffff:ffff::"
  IN6MASK128 = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

  def setup
    @in6_addr_any = IPAddr.new()
    @a = IPAddr.new("3ffe:505:2::/48")
    @b = IPAddr.new("0:0:0:1::")
    @c = IPAddr.new(IN6MASK32)
    @inconvertible_range = 1..5
    @inconvertible_string = "sometext"
  end
  alias set_up setup

  def test_or
    assert_equal("3ffe:505:2:1::", (@a | @b).to_s)
    a = @a
    a |= @b
    assert_equal("3ffe:505:2:1::", a.to_s)
    assert_equal("3ffe:505:2::", @a.to_s)
    assert_equal("3ffe:505:2:1::",
                 (@a | 0x00000000000000010000000000000000).to_s)
  end

  def test_and
    assert_equal("3ffe:505::", (@a & @c).to_s)
    a = @a
    a &= @c
    assert_equal("3ffe:505::", a.to_s)
    assert_equal("3ffe:505:2::", @a.to_s)
    assert_equal("3ffe:505::", (@a & 0xffffffff000000000000000000000000).to_s)
  end

  def test_shift_right
    assert_equal("0:3ffe:505:2::", (@a >> 16).to_s)
    a = @a
    a >>= 16
    assert_equal("0:3ffe:505:2::", a.to_s)
    assert_equal("3ffe:505:2::", @a.to_s)
  end

  def test_shift_left
    assert_equal("505:2::", (@a << 16).to_s)
    a = @a
    a <<= 16
    assert_equal("505:2::", a.to_s)
    assert_equal("3ffe:505:2::", @a.to_s)
  end

  def test_carrot
    a = ~@in6_addr_any
    assert_equal(IN6MASK128, a.to_s)
    assert_equal("::", @in6_addr_any.to_s)
  end

  def test_plus
    a = IPAddr.new("192.168.1.10")
    assert_equal("192.168.1.20", (a + 10).to_s)

    a = IPAddr.new("0.0.0.0")
    assert_equal("0.0.0.10", (a + 10).to_s)

    a = IPAddr.new("255.255.255.255")
    assert_raise(IPAddr::InvalidAddressError) { a + 10 }

    a = IPAddr.new("3ffe:505:2::a")
    assert_equal("3ffe:505:2::14", (a + 10).to_s)

    a = IPAddr.new("::")
    assert_equal("::a", (a + 10).to_s)

    a = IPAddr.new("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    assert_raise(IPAddr::InvalidAddressError) { a + 10 }
  end

  def test_minus
    a = IPAddr.new("192.168.1.10")
    assert_equal("192.168.1.0", (a - 10).to_s)

    a = IPAddr.new("0.0.0.0")
    assert_raise(IPAddr::InvalidAddressError) { a - 10 }

    a = IPAddr.new("255.255.255.255")
    assert_equal("255.255.255.245", (a - 10).to_s)

    a = IPAddr.new("3ffe:505:2::a")
    assert_equal("3ffe:505:2::", (a - 10).to_s)

    a = IPAddr.new("::")
    assert_raise(IPAddr::InvalidAddressError) { a - 10 }

    a = IPAddr.new("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    assert_equal("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff5", (a - 10).to_s)
  end

  def test_equal
    assert_equal(true, @a == IPAddr.new("3FFE:505:2::"))
    assert_equal(true, @a == IPAddr.new("3ffe:0505:0002::"))
    assert_equal(true, @a == IPAddr.new("3ffe:0505:0002:0:0:0:0:0"))
    assert_equal(false, @a == IPAddr.new("3ffe:505:3::"))
    assert_equal(true, @a != IPAddr.new("3ffe:505:3::"))
    assert_equal(false, @a != IPAddr.new("3ffe:505:2::"))
    assert_equal(false, @a == @inconvertible_range)
    assert_equal(false, @a == @inconvertible_string)
    assert_equal(false, IPAddr.new("0.0.0.0") == nil)
    assert_equal(false, IPAddr.new("::") == nil)
  end

  def test_compare
    assert_equal(nil, @a <=> @inconvertible_range)
    assert_equal(nil, @a <=> @inconvertible_string)
  end

  def test_mask
    a = @a.mask(32)
    assert_equal("3ffe:505::", a.to_s)
    assert_equal("3ffe:505::", @a.mask("ffff:ffff::").to_s)
    assert_equal("3ffe:505:2::", @a.to_s)
    a = IPAddr.new("192.168.2.0/24")
    assert_equal("192.168.0.0", a.mask(16).to_s)
    assert_equal("192.168.0.0", a.mask("255.255.0.0").to_s)
    assert_equal("192.168.2.0", a.to_s)
    assert_raise(IPAddr::InvalidPrefixError) {a.mask("255.255.0.255")}
    assert_raise(IPAddr::InvalidPrefixError) {@a.mask("ffff:1::")}
  end

  def test_include?
    assert_equal(true, @a.include?(IPAddr.new("3ffe:505:2::")))
    assert_equal(true, @a.include?(IPAddr.new("3ffe:505:2::1")))
    assert_equal(false, @a.include?(IPAddr.new("3ffe:505:3::")))
    net1 = IPAddr.new("192.168.2.0/24")
    assert_equal(true, net1.include?(IPAddr.new("192.168.2.0")))
    assert_equal(true, net1.include?(IPAddr.new("192.168.2.255")))
    assert_equal(false, net1.include?(IPAddr.new("192.168.3.0")))
    assert_equal(true, net1.include?(IPAddr.new("192.168.2.0/28")))
    assert_equal(false, net1.include?(IPAddr.new("192.168.2.0/16")))
    # test with integer parameter
    int = (192 << 24) + (168 << 16) + (2 << 8) + 13

    assert_equal(true, net1.include?(int))
    assert_equal(false, net1.include?(int+255))

  end

  def test_native_coerce_mask_addr
    assert_equal(IPAddr.new("0.0.0.2/255.255.255.255"), IPAddr.new("::2").native)
    assert_equal(IPAddr.new("0.0.0.2/255.255.255.255").to_range, IPAddr.new("::2").native.to_range)
  end

  def test_loopback?
    assert_equal(true,  IPAddr.new('127.0.0.1').loopback?)
    assert_equal(true,  IPAddr.new('127.127.1.1').loopback?)
    assert_equal(false, IPAddr.new('0.0.0.0').loopback?)
    assert_equal(false, IPAddr.new('192.168.2.0').loopback?)
    assert_equal(false, IPAddr.new('255.0.0.0').loopback?)
    assert_equal(true,  IPAddr.new('::1').loopback?)
    assert_equal(false, IPAddr.new('::').loopback?)
    assert_equal(false, IPAddr.new('3ffe:505:2::1').loopback?)

    assert_equal(true,  IPAddr.new('::ffff:127.0.0.1').loopback?)
    assert_equal(true,  IPAddr.new('::ffff:127.127.1.1').loopback?)
    assert_equal(false, IPAddr.new('::ffff:0.0.0.0').loopback?)
    assert_equal(false, IPAddr.new('::ffff:192.168.2.0').loopback?)
    assert_equal(false, IPAddr.new('::ffff:255.0.0.0').loopback?)

    # Global unicast addresses with 0xffff in group 5 must not be mistaken for ::ffff:127.x.x.x
    assert_equal(false, IPAddr.new('2001:db8:1:1:0:ffff:7f00:1').loopback?)
  end

  def test_private?
    assert_equal(false, IPAddr.new('0.0.0.0').private?)
    assert_equal(false, IPAddr.new('127.0.0.1').private?)

    assert_equal(false, IPAddr.new('8.8.8.8').private?)
    assert_equal(true,  IPAddr.new('10.0.0.0').private?)
    assert_equal(true,  IPAddr.new('10.255.255.255').private?)
    assert_equal(false, IPAddr.new('11.255.1.1').private?)

    assert_equal(false, IPAddr.new('172.15.255.255').private?)
    assert_equal(true,  IPAddr.new('172.16.0.0').private?)
    assert_equal(true,  IPAddr.new('172.31.255.255').private?)
    assert_equal(false, IPAddr.new('172.32.0.0').private?)

    assert_equal(false, IPAddr.new('190.168.0.0').private?)
    assert_equal(true,  IPAddr.new('192.168.0.0').private?)
    assert_equal(true,  IPAddr.new('192.168.255.255').private?)
    assert_equal(false, IPAddr.new('192.169.0.0').private?)

    assert_equal(false, IPAddr.new('169.254.0.1').private?)

    assert_equal(false, IPAddr.new('::1').private?)
    assert_equal(false, IPAddr.new('::').private?)

    assert_equal(false, IPAddr.new('fb84:8bf7:e905::1').private?)
    assert_equal(true,  IPAddr.new('fc84:8bf7:e905::1').private?)
    assert_equal(true,  IPAddr.new('fd84:8bf7:e905::1').private?)
    assert_equal(false, IPAddr.new('fe84:8bf7:e905::1').private?)

    assert_equal(false, IPAddr.new('::ffff:0.0.0.0').private?)
    assert_equal(false, IPAddr.new('::ffff:127.0.0.1').private?)

    assert_equal(false, IPAddr.new('::ffff:8.8.8.8').private?)
    assert_equal(true,  IPAddr.new('::ffff:10.0.0.0').private?)
    assert_equal(true,  IPAddr.new('::ffff:10.255.255.255').private?)
    assert_equal(false, IPAddr.new('::ffff:11.255.1.1').private?)

    assert_equal(false, IPAddr.new('::ffff:172.15.255.255').private?)
    assert_equal(true,  IPAddr.new('::ffff:172.16.0.0').private?)
    assert_equal(true,  IPAddr.new('::ffff:172.31.255.255').private?)
    assert_equal(false, IPAddr.new('::ffff:172.32.0.0').private?)

    assert_equal(false, IPAddr.new('::ffff:190.168.0.0').private?)
    assert_equal(true,  IPAddr.new('::ffff:192.168.0.0').private?)
    assert_equal(true,  IPAddr.new('::ffff:192.168.255.255').private?)
    assert_equal(false, IPAddr.new('::ffff:192.169.0.0').private?)

    assert_equal(false, IPAddr.new('::ffff:169.254.0.1').private?)

    # Global unicast addresses with 0xffff in group 5 must not be mistaken for ::ffff:10/172.16/192.168.x
    assert_equal(false, IPAddr.new('2001:718:1404:c8:0:ffff:ac19:c80e').private?)
    assert_equal(false, IPAddr.new('2001:db8:1:1:0:ffff:c0a8:1').private?)
  end

  def test_link_local?
    assert_equal(false, IPAddr.new('0.0.0.0').link_local?)
    assert_equal(false, IPAddr.new('127.0.0.1').link_local?)
    assert_equal(false, IPAddr.new('10.0.0.0').link_local?)
    assert_equal(false, IPAddr.new('172.16.0.0').link_local?)
    assert_equal(false, IPAddr.new('192.168.0.0').link_local?)

    assert_equal(true,  IPAddr.new('169.254.1.1').link_local?)
    assert_equal(true,  IPAddr.new('169.254.254.255').link_local?)

    assert_equal(false, IPAddr.new('::1').link_local?)
    assert_equal(false, IPAddr.new('::').link_local?)
    assert_equal(false, IPAddr.new('fb84:8bf7:e905::1').link_local?)

    assert_equal(true,  IPAddr.new('fe80::dead:beef:cafe:1234').link_local?)

    assert_equal(false, IPAddr.new('::ffff:0.0.0.0').link_local?)
    assert_equal(false, IPAddr.new('::ffff:127.0.0.1').link_local?)
    assert_equal(false, IPAddr.new('::ffff:10.0.0.0').link_local?)
    assert_equal(false, IPAddr.new('::ffff:172.16.0.0').link_local?)
    assert_equal(false, IPAddr.new('::ffff:192.168.0.0').link_local?)

    assert_equal(true,  IPAddr.new('::ffff:169.254.1.1').link_local?)
    assert_equal(true,  IPAddr.new('::ffff:169.254.254.255').link_local?)

    # Global unicast addresses with 0xffff in group 5 must not be mistaken for ::ffff:169.254.x.x
    assert_equal(false, IPAddr.new('2001:db8:1:1:0:ffff:a9fe:101').link_local?)
  end

  def test_multicast?
    assert_equal(true, IPAddr.new('224.0.0.0').multicast?)
    assert_equal(true, IPAddr.new('225.0.0.0').multicast?)
    assert_equal(true, IPAddr.new('224.0.0.0/4').multicast?)

    assert_equal(false, IPAddr.new('240.0.0.0').multicast?)
    assert_equal(false, IPAddr.new('240.0.0.0/4').multicast?)
    assert_equal(false, IPAddr.new('192.168.0.0').multicast?)
    assert_equal(false, IPAddr.new('169.254.1.1').multicast?)
    assert_equal(false, IPAddr.new('169.254.254.255').multicast?)

    assert_equal(true, IPAddr.new('ff00::').multicast?)
    assert_equal(true, IPAddr.new('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff').multicast?)
    assert_equal(true, IPAddr.new('ff00::/8').multicast?)

    assert_equal(false, IPAddr.new('feff::').multicast?)
    assert_equal(false, IPAddr.new('feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff').multicast?)
    assert_equal(false, IPAddr.new('fe00::/8').multicast?)
    assert_equal(false, IPAddr.new('::1').multicast?)
    assert_equal(false, IPAddr.new('::').multicast?)

    assert_equal(true, IPAddr.new('::ffff:224.0.0.0').multicast?)
    assert_equal(false, IPAddr.new('::ffff:240.0.0.0').multicast?)
  end

  def test_link_local_multicast?
    assert_equal(true, IPAddr.new('224.0.0.0').link_local_multicast?)
    assert_equal(true, IPAddr.new('224.0.0.0/24').link_local_multicast?)
    assert_equal(true, IPAddr.new('224.0.0.255').link_local_multicast?)

    assert_equal(false, IPAddr.new('224.0.1.1').link_local_multicast?)
    assert_equal(false, IPAddr.new('224.1.0.0').link_local_multicast?)

    assert_equal(false, IPAddr.new('225.0.0.0').link_local_multicast?)
    assert_equal(false, IPAddr.new('225.0.0.0/24').link_local_multicast?)
    assert_equal(false, IPAddr.new('192.168.0.0').link_local_multicast?)
    assert_equal(false, IPAddr.new('169.254.1.1').link_local_multicast?)
    assert_equal(false, IPAddr.new('169.254.254.255').link_local_multicast?)

    assert_equal(true, IPAddr.new('ff02::1').link_local_multicast?)
    assert_equal(true, IPAddr.new('ff02::/16').link_local_multicast?)

    assert_equal(false, IPAddr.new('ff00::').link_local_multicast?)
    assert_equal(false, IPAddr.new('ff03::1').link_local_multicast?)
    assert_equal(false, IPAddr.new('ff03::/16').link_local_multicast?)
    assert_equal(false, IPAddr.new('::1').link_local_multicast?)
    assert_equal(false, IPAddr.new('::').link_local_multicast?)

    assert_equal(true, IPAddr.new('::ffff:224.0.0.0').link_local_multicast?)
    assert_equal(true, IPAddr.new('::ffff:224.0.0.255').link_local_multicast?)
    assert_equal(false, IPAddr.new('::ffff:224.0.1.1').link_local_multicast?)
    assert_equal(false, IPAddr.new('::ffff:224.1.0.0').link_local_multicast?)
    assert_equal(false, IPAddr.new('::ffff:225.0.0.0').link_local_multicast?)
  end

  def test_hash
    a1 = IPAddr.new('192.168.2.0')
    a2 = IPAddr.new('192.168.2.0')
    a3 = IPAddr.new('3ffe:505:2::1')
    a4 = IPAddr.new('3ffe:505:2::1')
    a5 = IPAddr.new('127.0.0.1')
    a6 = IPAddr.new('::1')
    a7 = IPAddr.new('192.168.2.0/25')
    a8 = IPAddr.new('192.168.2.0/25')

    h = { a1 => 'ipv4', a2 => 'ipv4', a3 => 'ipv6', a4 => 'ipv6', a5 => 'ipv4', a6 => 'ipv6', a7 => 'ipv4', a8 => 'ipv4'}
    assert_equal(5, h.size)
    assert_equal('ipv4', h[a1])
    assert_equal('ipv4', h[a2])
    assert_equal('ipv6', h[a3])
    assert_equal('ipv6', h[a4])

    require 'set'
    s = Set[a1, a2, a3, a4, a5, a6, a7, a8]
    assert_equal(5, s.size)
    assert_equal(true, s.include?(a1))
    assert_equal(true, s.include?(a2))
    assert_equal(true, s.include?(a3))
    assert_equal(true, s.include?(a4))
    assert_equal(true, s.include?(a5))
    assert_equal(true, s.include?(a6))
  end

  def test_raises_invalid_address_error_with_error_message
    e = assert_raise(IPAddr::InvalidAddressError) do
      IPAddr.new('192.168.0.1000')
    end
    assert_equal('invalid address: 192.168.0.1000', e.message)

    e = assert_raise(IPAddr::InvalidAddressError) do
      IPAddr.new('192.168.01.100')
    end
    assert_equal('zero-filled number in IPv4 address is ambiguous: 192.168.01.100', e.message)

    e = assert_raise(IPAddr::InvalidAddressError) do
      IPAddr.new('INVALID')
    end
    assert_equal('invalid address: INVALID', e.message)
  end
end

class TC_IPAddrSourceSelection < Test::Unit::TestCase
  def select(dest, candidates, **opts)
    IPAddr.select_source(dest, candidates, **opts)
  end

  def test_default_policy_table
    table = IPAddr::DEFAULT_POLICY_TABLE
    assert_equal(9, table.size)
    assert_raise(FrozenError) { table << {} }
    assert_equal({ prefix: "::1/128", precedence: 50, label: 0 }, table.first)
    labels = table.map { |e| [e[:prefix], e[:label]] }
    assert_include(labels, ["::ffff:0:0/96", 4])
    assert_include(labels, ["fc00::/7", 13])
  end

  def test_scope_beats_longer_matching_prefix
    # The nearer prefix loses to the candidate with appropriate scope
    # because rule 2 is evaluated before rule 8.
    result = select("2001:db8:1::1", [
      { address: "2001:db8:1::5", prefix_length: 64, scope: IPAddr::SCOPE_LINK_LOCAL },
      { address: "2001:db8:2::5", prefix_length: 64, scope: IPAddr::SCOPE_GLOBAL },
    ])
    assert_equal("2001:db8:2::5", result.winner.address.to_s)
    elim = result.eliminations.find { |e| e.candidate.address.to_s == "2001:db8:1::5" }
    assert_equal("2", elim.rule)
    assert_equal("prefer appropriate scope", elim.rule_name)
  end

  def test_deprecated_fallback
    deprecated = { address: "2001:db8::2", deprecated: true }
    current = { address: "2001:db8::3" }

    result = select("2001:db8::1", [deprecated, current])
    assert_equal("2001:db8::3", result.winner.address.to_s)
    assert_equal("3", result.eliminations.first.rule)

    # With only deprecated candidates left, one is still selected.
    result = select("2001:db8::1", [deprecated])
    assert_equal(true, result.success?)
    assert_equal("2001:db8::2", result.winner.address.to_s)
    assert_empty(result.eliminations)
  end

  def test_complete_tie_keeps_first_candidate
    result = select("2001:db8::1", [
      { address: "2001:db8::5", interface: "eth0" },
      { address: "2001:db8::5", interface: "eth1" },
    ])
    assert_equal("eth0", result.winner.interface)
    elim = result.eliminations.first
    assert_nil(elim.rule)
    assert_nil(elim.rule_name)
    assert_equal("eth1", elim.candidate.interface)
  end

  def test_same_address_on_different_interfaces_are_distinct_candidates
    result = select("2001:db8::1", [
      { address: "2001:db8::5", interface: "eth0" },
      { address: "2001:db8::5", interface: "eth1" },
    ], outgoing_interface: "eth1")
    assert_equal("eth1", result.winner.interface)
    assert_equal(1, result.unavailable.size)
    assert_equal("eth0", result.unavailable.first.candidate.interface)
  end

  def test_destination_zone_restricts_candidates
    result = select("fe80::1%eth0", [
      { address: "fe80::2", interface: "eth1" },
      { address: "fe80::3", interface: "eth0" },
    ])
    assert_equal("fe80::3", result.winner.address.to_s)
    assert_equal(1, result.unavailable.size)
    assert_equal("fe80::2", result.unavailable.first.candidate.address.to_s)
  end

  def test_no_available_candidate
    result = select("fe80::1%eth0", [{ address: "fe80::2", interface: "eth1" }])
    assert_equal(false, result.success?)
    assert_nil(result.winner)
    assert_equal(1, result.unavailable.size)
  end

  def test_family_mismatch_is_unavailable
    result = select("192.0.2.1", [
      { address: "2001:db8::1" },
      { address: "192.0.2.9" },
    ])
    assert_equal("192.0.2.9", result.winner.address.to_s)
    assert_equal(1, result.unavailable.size)
  end

  def test_same_address_rule
    result = select("2001:db8::7", [
      { address: "2001:db8::8" },
      { address: "2001:db8::7" },
    ])
    assert_equal("2001:db8::7", result.winner.address.to_s)
    assert_equal("1", result.eliminations.first.rule)
  end

  def test_caller_supplied_policy_table_labels
    table = [
      { prefix: "2001:db8:1::/48", precedence: 45, label: 7 },
      { prefix: "::/0", precedence: 40, label: 1 },
    ]
    result = select("2001:db8:1::1", [
      { address: "2001:db8:2::77" },
      { address: "2001:db8:1::77" },
    ], policy_table: table)
    assert_equal("2001:db8:1::77", result.winner.address.to_s)
    assert_equal("6", result.eliminations.first.rule)
  end

  def test_home_address_preferred
    result = select("2001:db8::1", [
      { address: "2001:db8::3" },
      { address: "2001:db8::2", home: true },
    ])
    assert_equal("2001:db8::2", result.winner.address.to_s)
    assert_equal("4", result.eliminations.first.rule)
  end

  def test_temporary_preferred_unless_reversed
    public_addr = { address: "2001:db8::3" }
    temporary = { address: "2001:db8::2", temporary: true }

    result = select("2001:db8::1", [public_addr, temporary])
    assert_equal("2001:db8::2", result.winner.address.to_s)
    assert_equal("7", result.eliminations.first.rule)

    result = select("2001:db8::1", [public_addr, temporary], prefer_temporary: false)
    assert_equal("2001:db8::3", result.winner.address.to_s)
  end

  def test_next_hop_rule_and_unknown_route_information
    advertised = { address: "2001:db8::2", next_hop: "router-a" }
    other = { address: "2001:db8::3", next_hop: "router-b" }

    result = select("2001:db8::1", [other, advertised], next_hop: "router-a")
    assert_equal("2001:db8::2", result.winner.address.to_s)
    assert_equal("5.5", result.eliminations.first.rule)

    # Unknown route information is expressed by omitting next_hop;
    # rule 5.5 is skipped and the candidates tie.
    result = select("2001:db8::1", [other, advertised])
    assert_equal("2001:db8::3", result.winner.address.to_s)
    assert_nil(result.eliminations.first.rule)
  end

  def test_common_prefix_capped_at_candidate_prefix_length
    # 2001:db8:ab00::1 shares 40 bits with the destination, but its
    # prefix is only 16 bits long, so the common prefix length is
    # capped at 16 and loses against 34 bits.
    result = select("2001:db8:abcd::1", [
      { address: "2001:db8:ab00::1", prefix_length: 16 },
      { address: "2001:db8:8000::1", prefix_length: 64 },
    ])
    assert_equal("2001:db8:8000::1", result.winner.address.to_s)
    assert_equal("8", result.eliminations.first.rule)
  end

  def test_ipv4_mapped_destination
    result = select("::ffff:192.0.2.1", [
      { address: "2001:db8::1" },
      { address: "192.0.2.9" },
    ])
    assert_equal("192.0.2.9", result.winner.address.to_s)
    assert_equal("6", result.eliminations.first.rule)
  end

  def test_source_candidate_objects_are_accepted
    candidates = [
      IPAddr::SourceCandidate.new(address: "2001:db8::2", interface: "eth0"),
      IPAddr::SourceCandidate.new(address: IPAddr.new("2001:db8:abcd::3"), interface: "eth0"),
    ]
    result = select(IPAddr.new("2001:db8:abcd::1"), candidates)
    assert_same(candidates[1], result.winner)
    assert_same(candidates[0], result.eliminations.first.candidate)
  end
end
