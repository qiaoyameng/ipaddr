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

class TC_RPKIOriginValidation < Test::Unit::TestCase
  def test_valid_invalid_and_not_found
    view = IPAddr::RPKI::View.new([
      { prefix: "10.0.0.0/24", maxLength: 26, asn: 65000 },
      { prefix: "2001:db8::/32", maxLength: 48, asn: 65001 }
    ])

    valid = view.validate("10.0.0.0/25", 65000)
    assert_predicate(valid, :valid?)
    assert_equal(:valid, valid.status)
    assert_equal("Valid", valid.code)
    assert_equal("Valid", valid.to_s)
    assert_equal([["10.0.0.0/24", 26, 65000]], vrp_tuples(valid.authorizations))
    assert_empty(valid.rejections)

    invalid = view.validate("10.0.0.0/27", 65000)
    assert_predicate(invalid, :invalid?)
    assert_equal(:invalid, invalid.status)
    assert_equal("Invalid", invalid.code)
    assert_empty(invalid.authorizations)
    assert_equal([
      ["10.0.0.0/24", 26, 65000], :prefix_length_exceeds_max_length
    ], rejection_tuple(invalid.rejections.first))

    wrong_asn = view.validate("10.0.0.0/24", 65002)
    assert_predicate(wrong_asn, :invalid?)
    assert_equal(:origin_asn_mismatch, wrong_asn.rejections.first.reason)
    assert_match(/expected origin ASN 65000/, wrong_asn.rejections.first.message)

    not_found = view.validate("192.0.2.0/24", 65000)
    assert_predicate(not_found, :not_found?)
    assert_equal(:not_found, not_found.status)
    assert_equal("NotFound", not_found.code)
    assert_empty(not_found.authorizations)
    assert_empty(not_found.rejections)
  end

  def test_as0_always_rejects_origin_asns
    view = IPAddr::RPKI::View.new([
      ["10.0.0.0/24", 24, 0]
    ])

    result = view.validate("10.0.0.0/24", 65000)
    assert_predicate(result, :invalid?)
    assert_equal(:as0, result.rejections.first.reason)
    assert_equal(0, result.rejections.first.vrp.asn)
  end

  def test_allowing_vrp_wins_when_denying_vrp_also_covers
    view = IPAddr::RPKI::View.new([
      ["10.0.0.0/24", 24, 0],
      ["10.0.0.0/24", 24, 65000],
      ["10.0.0.0/23", 25, 65001]
    ])

    same_prefix = view.validate("10.0.0.0/24", 65000)
    assert_predicate(same_prefix, :valid?)
    assert_equal([["10.0.0.0/24", 24, 65000]],
                 vrp_tuples(same_prefix.authorizations))

    shorter_allow = view.validate("10.0.0.0/25", 65001)
    assert_predicate(shorter_allow, :valid?)
    assert_equal([["10.0.0.0/23", 25, 65001]],
                 vrp_tuples(shorter_allow.authorizations))

    invalid = view.validate("10.0.0.0/24", 65002)
    assert_predicate(invalid, :invalid?)
    reasons = invalid.rejections.map(&:reason).sort
    assert_equal([:as0, :origin_asn_mismatch, :origin_asn_mismatch], reasons)
  end

  def test_multiple_authorizations_and_dedupes_more_specific_max_length
    view = IPAddr::RPKI::View.new([
      ["10.0.0.0/22", 26, 65000],
      ["10.0.0.0/24", 25, 65000],
      ["10.0.0.0/24", 24, 65000]
    ])

    result = view.validate("10.0.0.0/25", 65000)
    assert_predicate(result, :valid?)
    assert_equal([
      ["10.0.0.0/24", 25, 65000],
      ["10.0.0.0/22", 26, 65000]
    ], vrp_tuples(result.authorizations))
    assert_equal(3, view.authorization_count)
  end

  def test_accepts_ipaddr_struct_and_string_keyed_hashes
    prefix = IPAddr.new("10.0.0.0/24")
    vrp = IPAddr::RPKI::VRP.new(prefix, 25, 65000)
    view = IPAddr::RPKI::View.new([
      vrp,
      { "prefix" => "192.0.2.0/24", "maxLength" => 24, "ASN" => 65001 }
    ])

    assert_predicate(view.validate(IPAddr.new("10.0.0.0/25"), 65000), :valid?)
    assert_predicate(view.validate("192.0.2.0/24", 65001), :valid?)
  end

  def test_ipv4_and_ipv6_are_separate
    view = IPAddr::RPKI::View.new([
      ["203.0.113.0/24", 24, 65000],
      ["2001:db8::/32", 32, 65000]
    ])

    assert_predicate(view.validate("203.0.113.0/24", 65000), :valid?)
    assert_predicate(view.validate("203.0.113.0/24", 65001), :invalid?)
    assert_predicate(view.validate("2001:db8::/32", 65000), :valid?)
    assert_predicate(view.validate("2001:db8::/48", 65000), :invalid?)
  end

  def test_snapshot_keeps_a_stable_version
    view = IPAddr::RPKI::View.new([["10.0.0.0/24", 24, 65000]])
    snapshot = view.snapshot

    assert_equal(1, view.version_number)
    assert_equal(1, snapshot.version_number)
    view.replace([["192.0.2.0/24", 24, 65001]])
    assert_equal(2, view.version_number)
    assert_equal(1, snapshot.version_number)
    assert_predicate(snapshot.validate("10.0.0.0/24", 65000), :valid?)
    assert_predicate(snapshot.validate("192.0.2.0/24", 65001), :not_found?)
    assert_predicate(view.validate("10.0.0.0/24", 65000), :not_found?)
    assert_predicate(view.validate("192.0.2.0/24", 65001), :valid?)
  end

  def test_failed_batch_validation_does_not_publish
    view = IPAddr::RPKI::View.new([["10.0.0.0/24", 24, 65000]])
    old_version = view.version

    assert_raise(IPAddr::RPKI::InvalidVRPError) do
      view.replace([
        ["192.0.2.0/24", 24, 65001],
        ["192.0.2.0/24", 23, 65001]
      ])
    end
    assert_same(old_version, view.version)
    assert_equal(1, view.version_number)
    assert_equal(1, view.authorization_count)
    assert_predicate(view.validate("10.0.0.0/24", 65000), :valid?)
    assert_predicate(view.validate("192.0.2.0/24", 65001), :not_found?)
  end

  def test_invalid_vrps
    view = IPAddr::RPKI::View.new

    [
      [["10.0.0.0/24", 23, 65000], /maxLength 23 is outside 24/],
      [["10.0.0.0/24", 33, 65000], /maxLength 33 is outside/],
      [["2001:db8::/32", 129, 65000], /maxLength 129 is outside/],
      [["10.0.0.1/24", 24, 65000], /host bits/],
      [["10.0.0.0/24", 24, -1], /ASN must be an integer/],
      [["10.0.0.0/24", 24, 4294967296], /ASN must be an integer/],
      [["10.0.0.0/24", "24", 65000], /maxLength must be an integer/]
    ].each do |vrp, message|
      e = assert_raise(IPAddr::RPKI::InvalidVRPError) do
        view.replace([vrp])
      end
      assert_match(message, e.message)
      assert_equal(0, view.authorization_count)
    end

  end

  def test_small_ipv4_domain_matches_naive_reference
    assert_matches_naive_reference("10.0.0.0", 32, 1)
  end

  def test_small_ipv6_domain_matches_naive_reference
    assert_matches_naive_reference("2001:db8::", 128, 1)
  end

  private

  def vrp_tuples(vrps)
    vrps.map { |vrp| [vrp.prefix.cidr, vrp.max_length, vrp.asn] }
  end

  def rejection_tuple(rejection)
    [
      [rejection.vrp.prefix.cidr, rejection.vrp.max_length, rejection.vrp.asn],
      rejection.reason
    ]
  end

  def assert_matches_naive_reference(base, total_length, domain_bits)
    candidates = exhaustive_vrps(base, total_length, domain_bits)
    mismatches = []

    0.upto((1 << candidates.size) - 1) do |mask|
      vrps = candidates.each_with_index.select { |_, index|
        mask[index] == 1
      }.map(&:first)

      view = IPAddr::RPKI::View.new(vrps)

      0.upto(domain_bits) do |route_length|
        0.upto((1 << route_length) - 1) do |subnet|
          address = (subnet << (domain_bits - route_length))
          prefix_length = total_length - domain_bits + route_length
          route = route_cidr(base, address, prefix_length)

          [0, 65000, 65001, 65002].each do |asn|
            expected = naive_validation(vrps, route, asn)
            actual = view.validate(route, asn)
            actual_authorizations = vrp_tuples(actual.authorizations).sort
            expected_authorizations = expected[:authorizations].sort
            actual_rejections =
              if actual.invalid?
                actual.rejections.map { |rejection|
                  rejection_tuple(rejection).flatten
                }.sort
              else
                []
              end
            expected_rejections =
              if expected[:status] == :invalid
                expected[:rejections].sort
              else
                []
              end
            observed = {
              status: actual.status,
              code: actual.code,
              authorizations: actual_authorizations,
              rejections: actual_rejections
            }
            expected_observation = {
              status: expected[:status],
              code: rfc_code(expected[:status]),
              authorizations: expected_authorizations,
              rejections: expected_rejections
            }
            mismatches << [vrps, route, asn, expected_observation, observed] if
              observed != expected_observation
          end
        end
      end
    end

    assert_empty(mismatches, mismatches.first(3).inspect)
  end

  def exhaustive_vrps(base, total_length, domain_bits)
    0.upto(domain_bits).flat_map { |prefix_length|
      0.upto((1 << prefix_length) - 1).flat_map { |subnet|
        address = subnet << (domain_bits - prefix_length)
        (prefix_length..domain_bits).flat_map { |max_length|
          [0, 65000, 65001].map { |asn|
            [route_cidr(base, address, total_length - domain_bits + prefix_length),
             total_length - domain_bits + max_length, asn]
          }
        }
      }
    }
  end

  def route_cidr(base, host, prefix_length)
    network = IPAddr.new(base)
    IPAddr.new(network.to_i | host, network.family).mask(prefix_length).cidr
  end

  def rfc_code(status)
    {
      valid: "Valid",
      invalid: "Invalid",
      not_found: "NotFound"
    }.fetch(status)
  end

  def naive_validation(vrps, route, origin_asn)
    route_network = IPAddr.new(route)
    family = IPAddr.new(route.split("/", 2).first).family
    route_address = route_network.to_i
    route_length = route_network.prefix
    covering = vrps.select { |prefix, _, asn|
      network = IPAddr.new(prefix)
      next false unless network.family == family

      network_prefix = network.prefix
      next false unless route_length >= network_prefix
      next false unless (route_address >> (total_length(family) - network_prefix)) ==
                        (network.to_i >> (total_length(family) - network_prefix))

      true
    }

    return { status: :not_found, authorizations: [], rejections: [] } if
      covering.empty?

    authorizations = covering.select { |_, max_length, asn|
      asn != 0 && asn == origin_asn && max_length >= route_length
    }.map { |prefix, max_length, asn|
      [prefix, max_length, asn]
    }.uniq

    rejections = covering.reject { |_, max_length, asn|
      asn != 0 && asn == origin_asn && max_length >= route_length
    }.map { |prefix, max_length, asn|
      reason = if asn == 0
                 :as0
               elsif asn == origin_asn
                 :prefix_length_exceeds_max_length
               else
                 :origin_asn_mismatch
               end
      [prefix, max_length, asn, reason]
    }.uniq

    {
      status: authorizations.empty? ? :invalid : :valid,
      authorizations: authorizations,
      rejections: rejections
    }
  end

  def total_length(family)
    family == Socket::AF_INET ? 32 : 128
  end

end
