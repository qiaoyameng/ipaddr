# frozen_string_literal: true
#
# ipaddr.rb - A class to manipulate an IP address
#
# Copyright (c) 2002 Hajimu UMEMOTO <ume@mahoroba.org>.
# Copyright (c) 2007, 2009, 2012 Akinori MUSHA <knu@iDaemons.org>.
# All rights reserved.
#
# You can redistribute and/or modify it under the same terms as Ruby.
#
# $Id$
#
# Contact:
#   - Akinori MUSHA <knu@iDaemons.org> (current maintainer)
#
# TODO:
#   - scope_id support
#
require 'socket'

# IPAddr provides a set of methods to manipulate an IP address.  Both IPv4 and
# IPv6 are supported.
#
# == Example
#
#   require 'ipaddr'
#
#   ipaddr1 = IPAddr.new "3ffe:505:2::1"
#
#   p ipaddr1                   #=> #<IPAddr: IPv6:3ffe:0505:0002:0000:0000:0000:0000:0001/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff>
#
#   p ipaddr1.to_s              #=> "3ffe:505:2::1"
#
#   ipaddr2 = ipaddr1.mask(48)  #=> #<IPAddr: IPv6:3ffe:0505:0002:0000:0000:0000:0000:0000/ffff:ffff:ffff:0000:0000:0000:0000:0000>
#
#   p ipaddr2.to_s              #=> "3ffe:505:2::"
#
#   ipaddr3 = IPAddr.new "192.168.2.0/24"
#
#   p ipaddr3                   #=> #<IPAddr: IPv4:192.168.2.0/255.255.255.0>

class IPAddr
  # The version string
  VERSION = "1.2.9"

  # 32 bit mask for IPv4
  IN4MASK = 0xffffffff
  # 128 bit mask for IPv6
  IN6MASK = 0xffffffffffffffffffffffffffffffff
  # Format string for IPv6
  IN6FORMAT = (["%.4x"] * 8).join(':').freeze

  # Regexp _internally_ used for parsing IPv4 address.
  RE_IPV4ADDRLIKE = %r{
    \A
    \d+ \. \d+ \. \d+ \. \d+
    \z
  }x

  # Regexp _internally_ used for parsing IPv6 address.
  RE_IPV6ADDRLIKE_FULL = %r{
    \A
    (?:
      (?: [\da-f]{1,4} : ){7} [\da-f]{1,4}
    |
      ( (?: [\da-f]{1,4} : ){6} )
      (\d+) \. (\d+) \. (\d+) \. (\d+)
    )
    \z
  }xi

  # Regexp _internally_ used for parsing IPv6 address.
  RE_IPV6ADDRLIKE_COMPRESSED = %r{
    \A
    ( (?: (?: [\da-f]{1,4} : )* [\da-f]{1,4} )? )
    ::
    ( (?:
      ( (?: [\da-f]{1,4} : )* )
      (?:
        [\da-f]{1,4}
      |
        (\d+) \. (\d+) \. (\d+) \. (\d+)
      )
    )? )
    \z
  }xi

  # Generic IPAddr related error. Exceptions raised in this class should
  # inherit from Error.
  class Error < ArgumentError; end

  # Raised when the provided IP address is an invalid address.
  class InvalidAddressError < Error; end

  # Raised when the address family is invalid such as an address with an
  # unsupported family, an address with an inconsistent family, or an address
  # who's family cannot be determined.
  class AddressFamilyError < Error; end

  # Raised when the address is an invalid length.
  class InvalidPrefixError < InvalidAddressError; end

  # Returns the address family of this IP address.
  attr_reader :family

  # Creates a new ipaddr containing the given network byte ordered
  # string form of an IP address.
  def self.new_ntoh(addr)
    return new(ntop(addr))
  end

  # Convert a network byte ordered string form of an IP address into
  # human readable form.
  # It expects the string to be encoded in Encoding::ASCII_8BIT (BINARY).
  def self.ntop(addr)
    if addr.is_a?(String) && addr.encoding != Encoding::BINARY
      raise InvalidAddressError, "invalid encoding (given #{addr.encoding}, expected BINARY)"
    end

    case addr.bytesize
    when 4
      addr.unpack('C4').join('.')
    when 16
      IN6FORMAT % addr.unpack('n8')
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end

  # Returns a new ipaddr built by bitwise AND.
  def &(other)
    return self.clone.set(@addr & coerce_other(other).to_i)
  end

  # Returns a new ipaddr built by bitwise OR.
  def |(other)
    return self.clone.set(@addr | coerce_other(other).to_i)
  end

  # Returns a new ipaddr built by bitwise right-shift.
  def >>(num)
    return self.clone.set(@addr >> num)
  end

  # Returns a new ipaddr built by bitwise left shift.
  def <<(num)
    return self.clone.set(addr_mask(@addr << num))
  end

  # Returns a new ipaddr built by bitwise negation.
  def ~
    return self.clone.set(addr_mask(~@addr))
  end

  # Returns a new ipaddr greater than the original address by offset
  def +(offset)
    self.clone.set(@addr + offset, @family)
  end

  # Returns a new ipaddr less than the original address by offset
  def -(offset)
    self.clone.set(@addr - offset, @family)
  end

  # Returns true if two ipaddrs are equal.
  def ==(other)
    if other.nil?
      return false
    end

    other = coerce_other(other)
  rescue
    false
  else
    @family == other.family && @addr == other.to_i
  end

  # Returns a new ipaddr built by masking IP address with the given
  # prefixlen/netmask. (e.g. 8, 64, "255.255.255.0", etc.)
  def mask(prefixlen)
    return self.clone.mask!(prefixlen)
  end

  # Returns true if the given ipaddr is in the range.
  #
  # e.g.:
  #   require 'ipaddr'
  #   net1 = IPAddr.new("192.168.2.0/24")
  #   net2 = IPAddr.new("192.168.2.100")
  #   net3 = IPAddr.new("192.168.3.0")
  #   net4 = IPAddr.new("192.168.2.0/16")
  #   p net1.include?(net2)     #=> true
  #   p net1.include?(net3)     #=> false
  #   p net1.include?(net4)     #=> false
  #   p net4.include?(net1)     #=> true
  def include?(other)
    other = coerce_other(other)
    return false unless other.family == family
    begin_addr <= other.begin_addr && end_addr >= other.end_addr
  end
  alias === include?

  # Returns the integer representation of the ipaddr.
  def to_i
    return @addr
  end

  # Returns a string containing the IP address representation.
  def to_s
    str = to_string
    return str if ipv4?

    str.gsub!(/\b0{1,3}([\da-f]+)\b/i, '\1')
    loop do
      break if str.sub!(/\A0:0:0:0:0:0:0:0\z/, '::')
      break if str.sub!(/\b0:0:0:0:0:0:0\b/, ':')
      break if str.sub!(/\b0:0:0:0:0:0\b/, ':')
      break if str.sub!(/\b0:0:0:0:0\b/, ':')
      break if str.sub!(/\b0:0:0:0\b/, ':')
      break if str.sub!(/\b0:0:0\b/, ':')
      break if str.sub!(/\b0:0\b/, ':')
      break
    end
    str.sub!(/:{3,}/, '::')

    if /\A::(ffff:)?([\da-f]{1,4}):([\da-f]{1,4})\z/i =~ str
      str = sprintf('::%s%d.%d.%d.%d', $1, $2.hex / 256, $2.hex % 256, $3.hex / 256, $3.hex % 256)
    end

    str
  end

  # Returns a string containing the IP address representation in
  # canonical form.
  def to_string
    str = _to_string(@addr)

    if @family == Socket::AF_INET6
      str << zone_id.to_s
    end

    return str
  end

  # Returns a string containing the IP address representation with prefix.
  def as_json(*)
    if ipv4? && prefix == 32
      to_s
    elsif ipv6? && prefix == 128
      to_s
    else
      cidr
    end
  end

  # Returns a json string containing the IP address representation.
  def to_json(*a)
    %Q{"#{as_json(*a)}"}
  end

  # Returns a string containing the IP address representation in
  # cidr notation
  def cidr
    "#{to_s}/#{prefix}"
  end

  # Returns a network byte ordered string form of the IP address.
  def hton
    case @family
    when Socket::AF_INET
      return [@addr].pack('N')
    when Socket::AF_INET6
      return (0..7).map { |i|
        (@addr >> (112 - 16 * i)) & 0xffff
      }.pack('n8')
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end

  # Returns true if the ipaddr is an IPv4 address.
  def ipv4?
    return @family == Socket::AF_INET
  end

  # Returns true if the ipaddr is an IPv6 address.
  def ipv6?
    return @family == Socket::AF_INET6
  end

  # Returns true if the ipaddr is a loopback address.
  # Loopback IPv4 addresses in the IPv4-mapped IPv6
  # address range are also considered as loopback addresses.
  def loopback?
    case @family
    when Socket::AF_INET
      @addr & 0xff000000 == 0x7f000000 # 127.0.0.1/8
    when Socket::AF_INET6
      @addr == 1 || # ::1
        (@addr >> 32 == 0xffff && (
          @addr & 0xff000000 == 0x7f000000 # ::ffff:127.0.0.1/8
        ))
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end

  # Returns true if the ipaddr is a private address.  IPv4 addresses
  # in 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16 as defined in RFC
  # 1918 and IPv6 Unique Local Addresses in fc00::/7 as defined in RFC
  # 4193 are considered private. Private IPv4 addresses in the
  # IPv4-mapped IPv6 address range are also considered private.
  def private?
    case @family
    when Socket::AF_INET
      @addr & 0xff000000 == 0x0a000000 ||    # 10.0.0.0/8
        @addr & 0xfff00000 == 0xac100000 ||  # 172.16.0.0/12
        @addr & 0xffff0000 == 0xc0a80000     # 192.168.0.0/16
    when Socket::AF_INET6
      @addr & 0xfe00_0000_0000_0000_0000_0000_0000_0000 == 0xfc00_0000_0000_0000_0000_0000_0000_0000 ||
        (@addr >> 32 == 0xffff && (
          @addr & 0xff000000 == 0x0a000000 ||  # ::ffff:10.0.0.0/8
          @addr & 0xfff00000 == 0xac100000 ||  # ::ffff:172.16.0.0/12
          @addr & 0xffff0000 == 0xc0a80000     # ::ffff:192.168.0.0/16
        ))
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end

  # Returns true if the ipaddr is a link-local unicast address.  IPv4
  # addresses in 169.254.0.0/16 reserved by RFC 3927 and link-local
  # IPv6 Unicast Addresses in fe80::/10 reserved by RFC 4291 are
  # considered link-local. Link-local IPv4 addresses in the
  # IPv4-mapped IPv6 address range are also considered link-local.
  def link_local?
    case @family
    when Socket::AF_INET
      @addr & 0xffff0000 == 0xa9fe0000 # 169.254.0.0/16
    when Socket::AF_INET6
      @addr & 0xffc0_0000_0000_0000_0000_0000_0000_0000 == 0xfe80_0000_0000_0000_0000_0000_0000_0000 || # fe80::/10
        (@addr >> 32 == 0xffff && (
          @addr & 0xffff0000 == 0xa9fe0000 # ::ffff:169.254.0.0/16
        ))
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end

  alias link_local_unicast? link_local?

  # Returns true if the ipaddr is a multicast address. IPv4
  # addresses in 224.0.0.0/4 and IPv6 multicast addresses
  # in ff00::/8 are considered multicast. Multicast IPv4 addresses in the
  # IPv4-mapped IPv6 address range are also considered multicast.
  def multicast?
    case @family
    when Socket::AF_INET
      @addr & 0xf0000000 == 0xe0000000 # 224.0.0.0/4
    when Socket::AF_INET6
      @addr & 0xff00_0000_0000_0000_0000_0000_0000_0000 == 0xff00_0000_0000_0000_0000_0000_0000_0000 || # ff00::/8
        (@addr >> 32 == 0xffff &&
          @addr & 0xf0000000 == 0xe0000000 # ::ffff:224.0.0.0/4
        )
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end

  # Returns true if the ipaddr is a link-local multicast address. IPv4
  # addresses in 224.0.0.0/24 and link-local IPv6 Multicast Addresses in ff02::/16
  # are considered link-local multicast. Link-local multicast IPv4 addresses in the
  # IPv4-mapped IPv6 address range are also considered link-local multicast.
  def link_local_multicast?
    case @family
    when Socket::AF_INET
      @addr & 0xffffff00 == 0xe0000000 # 224.0.0.0/24 Local Network Control Block
    when Socket::AF_INET6
      @addr & 0xffff_0000_0000_0000_0000_0000_0000_0000 == 0xff02_0000_0000_0000_0000_0000_0000_0000 || # ff02::/16
        (@addr >> 32 == 0xffff && (
          @addr & 0xffffff00 == 0xe0000000 # ::ffff:224.0.0.0/24
        ))
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end

  # Returns true if the ipaddr is an IPv4-mapped IPv6 address.
  def ipv4_mapped?
    return ipv6? && (@addr >> 32) == 0xffff
  end

  # Returns true if the ipaddr is an IPv4-compatible IPv6 address.
  def ipv4_compat?
    warn "IPAddr\##{__callee__} is obsolete", uplevel: 1 if $VERBOSE
    _ipv4_compat?
  end

  def _ipv4_compat?             # :nodoc:
    if !ipv6? || (@addr >> 32) != 0
      return false
    end
    a = (@addr & IN4MASK)
    return a != 0 && a != 1
  end

  private :_ipv4_compat?

  # Returns a new ipaddr built by converting the native IPv4 address
  # into an IPv4-mapped IPv6 address.
  def ipv4_mapped
    if !ipv4?
      raise InvalidAddressError, "not an IPv4 address: #{to_s}"
    end
    clone = self.clone.set(@addr | 0xffff00000000, Socket::AF_INET6)
    clone.instance_variable_set(:@mask_addr, @mask_addr | 0xffffffffffffffffffffffff00000000)
    clone
  end

  # Returns a new ipaddr built by converting the native IPv4 address
  # into an IPv4-compatible IPv6 address.
  def ipv4_compat
    warn "IPAddr\##{__callee__} is obsolete", uplevel: 1 if $VERBOSE
    if !ipv4?
      raise InvalidAddressError, "not an IPv4 address: #{to_s}"
    end
    clone = self.clone.set(@addr, Socket::AF_INET6)
    clone.instance_variable_set(:@mask_addr, @mask_addr | 0xffffffffffffffffffffffff00000000)
    clone
  end

  # Returns a new ipaddr built by converting the IPv6 address into a
  # native IPv4 address.  If the IP address is not an IPv4-mapped or
  # IPv4-compatible IPv6 address, returns self.
  def native
    if !ipv4_mapped? && !_ipv4_compat?
      return self
    end
    return self.clone.set(@addr & IN4MASK, Socket::AF_INET)
  end

  # Returns a string for DNS reverse lookup.  It returns a string in
  # RFC3172 form for an IPv6 address.
  def reverse
    case @family
    when Socket::AF_INET
      return _reverse + ".in-addr.arpa"
    when Socket::AF_INET6
      return ip6_arpa
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end

  # Returns a string for DNS reverse lookup compatible with RFC3172.
  def ip6_arpa
    if !ipv6?
      raise InvalidAddressError, "not an IPv6 address: #{to_s}"
    end
    return _reverse + ".ip6.arpa"
  end

  # Returns a string for DNS reverse lookup compatible with RFC1886.
  def ip6_int
    if !ipv6?
      raise InvalidAddressError, "not an IPv6 address: #{to_s}"
    end
    return _reverse + ".ip6.int"
  end

  # Returns the successor to the ipaddr.
  def succ
    return self.clone.set(@addr + 1, @family)
  end

  # Compares the ipaddr with another.
  def <=>(other)
    other = coerce_other(other)
  rescue
    nil
  else
    @addr <=> other.to_i if other.family == @family
  end
  include Comparable

  # Checks equality used by Hash.
  def eql?(other)
    return self.class == other.class && self.hash == other.hash && self == other
  end

  # Returns a hash value used by Hash, Set, and Array classes
  def hash
    return ([@addr, @mask_addr, @zone_id].hash << 1) | (ipv4? ? 0 : 1)
  end

  # Creates a Range object for the network address.
  def to_range
    self.class.new(begin_addr, @family)..self.class.new(end_addr, @family)
  end

  # Returns the prefix length in bits for the ipaddr.
  def prefix
    case @family
    when Socket::AF_INET
      n = IN4MASK ^ @mask_addr
      i = 32
    when Socket::AF_INET6
      n = IN6MASK ^ @mask_addr
      i = 128
    else
      raise AddressFamilyError, "unsupported address family"
    end
    while n.positive?
      n >>= 1
      i -= 1
    end
    i
  end

  # Sets the prefix length in bits
  def prefix=(prefix)
    case prefix
    when Integer
      mask!(prefix)
    else
      raise InvalidPrefixError, "prefix must be an integer"
    end
  end

  # Returns a string containing a human-readable representation of the
  # ipaddr. ("#<IPAddr: family:address/mask>")
  def inspect
    case @family
    when Socket::AF_INET
      af = "IPv4"
    when Socket::AF_INET6
      af = "IPv6"
      zone_id = @zone_id.to_s
    else
      raise AddressFamilyError, "unsupported address family"
    end
    return sprintf("#<%s: %s:%s%s/%s>", self.class.name,
                   af, _to_string(@addr), zone_id, _to_string(@mask_addr))
  end

  # Returns the netmask in string format e.g. 255.255.0.0
  def netmask
    _to_string(@mask_addr)
  end

  # Returns the wildcard mask in string format e.g. 0.0.255.255
  def wildcard_mask
    case @family
    when Socket::AF_INET
      mask = IN4MASK ^ @mask_addr
    when Socket::AF_INET6
      mask = IN6MASK ^ @mask_addr
    else
      raise AddressFamilyError, "unsupported address family"
    end

    _to_string(mask)
  end

  # Returns the IPv6 zone identifier, if present.
  # Raises InvalidAddressError if not an IPv6 address.
  def zone_id
    if @family == Socket::AF_INET6
      @zone_id
    else
      raise InvalidAddressError, "not an IPv6 address"
    end
  end

  # Returns the IPv6 zone identifier, if present.
  # Raises InvalidAddressError if not an IPv6 address.
  def zone_id=(zid)
    if @family == Socket::AF_INET6
      case zid
      when nil, /\A%(\w+)\z/
        @zone_id = zid
      else
        raise InvalidAddressError, "invalid zone identifier for address"
      end
    else
      raise InvalidAddressError, "not an IPv6 address"
    end
  end

  # == RFC 6724 Source Address Selection
  #
  # The following constants, classes and methods implement an offline
  # simulation of the source address selection algorithm defined by
  # RFC 6724 Section 5.  Every input the algorithm needs (candidate
  # attributes, outgoing interface, next hop, policy table) is passed
  # explicitly by the caller; the state of the machine running this
  # code is never consulted.

  # Interface-local scope (loopback addresses).
  SCOPE_INTERFACE_LOCAL = 1
  # Link-local scope.
  SCOPE_LINK_LOCAL = 2
  # Admin-local scope.
  SCOPE_ADMIN_LOCAL = 4
  # Site-local scope (deprecated by RFC 3879, kept for completeness).
  SCOPE_SITE_LOCAL = 5
  # Organization-local scope.
  SCOPE_ORGANIZATION_LOCAL = 8
  # Global scope.
  SCOPE_GLOBAL = 14

  # The default policy table defined by RFC 6724 Section 2.1.  Each
  # entry is a Hash with :prefix, :precedence and :label keys.  A
  # caller supplied table passed to IPAddr.select_source must use the
  # same shape.
  DEFAULT_POLICY_TABLE = [
    { prefix: "::1/128",       precedence: 50, label: 0 },
    { prefix: "::/0",          precedence: 40, label: 1 },
    { prefix: "::ffff:0:0/96", precedence: 35, label: 4 },
    { prefix: "2002::/16",     precedence: 30, label: 2 },
    { prefix: "2001::/32",     precedence: 5,  label: 5 },
    { prefix: "fc00::/7",      precedence: 3,  label: 13 },
    { prefix: "::/96",         precedence: 1,  label: 3 },
    { prefix: "fec0::/10",     precedence: 1,  label: 11 },
    { prefix: "3ffe::/16",     precedence: 1,  label: 12 },
  ].each(&:freeze).freeze

  # Names of the RFC 6724 source address selection rules, keyed by the
  # rule identifier used in SourceElimination#rule.
  SOURCE_SELECTION_RULES = {
    "1"   => "prefer same address",
    "2"   => "prefer appropriate scope",
    "3"   => "avoid deprecated addresses",
    "4"   => "prefer home addresses",
    "5"   => "prefer outgoing interface",
    "5.5" => "prefer address in a prefix advertised by the next-hop",
    "6"   => "prefer matching label",
    "7"   => "prefer temporary addresses",
    "8"   => "use longest matching prefix",
  }.freeze

  # A single source address candidate for IPAddr.select_source.  Two
  # candidates are never considered equal just because they hold the
  # same address: the same address assigned to different interfaces
  # yields distinct candidates.
  class SourceCandidate
    # The candidate address (IPAddr).
    attr_reader :address
    # Name of the interface the address is assigned to, or nil.
    attr_reader :interface
    # Length in bits of the prefix the address belongs to.  The common
    # prefix length used by rule 8 never exceeds this value.
    attr_reader :prefix_length
    # RFC 6724 scope of the address (see the SCOPE_* constants).
    attr_reader :scope
    # Next hop (router) that advertised the prefix of this address, or
    # nil when the route information is unknown.  Used by rule 5.5.
    attr_reader :next_hop

    def initialize(address:, interface: nil, prefix_length: nil, scope: nil,
                   deprecated: false, temporary: false, home: false, next_hop: nil)
      @address = address.is_a?(IPAddr) ? address : IPAddr.new(address)
      @interface = interface
      @prefix_length = prefix_length || (@address.ipv4? ? 32 : 128)
      @scope = scope || IPAddr.send(:rfc6724_scope, @address)
      @deprecated = deprecated ? true : false
      @temporary = temporary ? true : false
      @home = home ? true : false
      @next_hop = next_hop
    end

    # Whether the address is deprecated (RFC 4862).
    def deprecated?
      @deprecated
    end

    # Whether the address is a temporary address (RFC 4941).
    def temporary?
      @temporary
    end

    # Whether the address is a mobile home address (RFC 6275); an
    # address that is not a home address acts as a care-of address.
    def home?
      @home
    end

    def to_s
      str = @address.to_s
      str << "%#{@interface}" if @interface
      str
    end

    def inspect
      flags = []
      flags << "deprecated" if deprecated?
      flags << "temporary" if temporary?
      flags << "home" if home?
      "#<IPAddr::SourceCandidate #{self} scope=#{@scope} prefix_length=#{@prefix_length}" \
        "#{flags.empty? ? '' : ' ' + flags.join(' ')}>"
    end
  end

  # Record describing why one candidate lost against another.  The
  # candidate is always eliminated on the first rule that
  # distinguishes it from the candidate it was compared with.
  SourceElimination = Struct.new(:candidate, :rule, :rule_name, :reason, keyword_init: true)

  # Record describing a candidate that did not take part in the rule
  # comparison at all (wrong address family, different zone, or not on
  # the outgoing interface).
  UnavailableCandidate = Struct.new(:candidate, :reason, keyword_init: true)

  # The outcome of IPAddr.select_source.
  class SourceSelection
    # The destination the selection ran for (IPAddr).
    attr_reader :destination
    # The selected SourceCandidate, or nil when no candidate was
    # available.
    attr_reader :winner
    # Array of SourceElimination, one per candidate that lost a
    # pairwise comparison, in the order the comparisons happened.
    attr_reader :eliminations
    # Array of UnavailableCandidate for candidates excluded before the
    # rule comparison.
    attr_reader :unavailable

    def initialize(destination:, winner:, eliminations:, unavailable:)
      @destination = destination
      @winner = winner
      @eliminations = eliminations.freeze
      @unavailable = unavailable.freeze
    end

    # Whether a source address could be selected.
    def success?
      !@winner.nil?
    end
  end

  # Selects the most appropriate source address candidate for reaching
  # +destination+ following the RFC 6724 source address selection
  # algorithm (Section 5).  This is a pure, offline simulation: every
  # piece of information the algorithm needs is taken from the
  # explicit arguments and the state of the running machine is never
  # consulted.
  #
  # +destination+ may be an IPAddr or a String, optionally carrying an
  # IPv6 zone (e.g. "fe80::1%eth0").  +candidates+ is a list of
  # IPAddr::SourceCandidate objects or of Hashes accepted by
  # IPAddr::SourceCandidate.new.
  #
  # Candidates whose address family does not match the destination
  # (an IPv4 candidate still matches an IPv4-mapped IPv6 destination),
  # that are not assigned to the destination zone, or that are not on
  # the +outgoing_interface+ when one is given, are unavailable and do
  # not take part in the rule comparison.  The remaining candidates
  # are compared pairwise with the RFC 6724 rules in their specified
  # order; the first rule that distinguishes two candidates decides
  # between them, so the factors are never merged into a single score.
  #
  # +policy_table+ is the caller supplied label table (see
  # IPAddr::DEFAULT_POLICY_TABLE for the shape).  +next_hop+ is the
  # router that will be used to reach the destination; when it is nil
  # (unknown route information) rule 5.5 is simply skipped.
  # +prefer_temporary+ may be set to false to reverse rule 7.
  #
  # Returns an IPAddr::SourceSelection describing the winner, the
  # unavailable candidates, and, for every eliminated candidate, the
  # first rule on which it lost and why.
  def self.select_source(destination, candidates, policy_table: DEFAULT_POLICY_TABLE,
                         outgoing_interface: nil, next_hop: nil, prefer_temporary: true)
    dest = destination.is_a?(IPAddr) ? destination : IPAddr.new(destination)
    zone = dest.ipv6? && dest.zone_id ? dest.zone_id.sub(/\A%/, "") : nil
    effective_interface = outgoing_interface || zone

    table = compile_policy_table(policy_table)
    dest_label = policy_label(table, dest)
    dest_scope = rfc6724_scope(dest)

    available = []
    unavailable = []
    candidates.each do |c|
      candidate = c.is_a?(SourceCandidate) ? c : SourceCandidate.new(**c)
      if !source_family_compatible?(candidate.address, dest)
        unavailable << UnavailableCandidate.new(
          candidate: candidate,
          reason: "address family does not match the destination address family")
      elsif zone && candidate.interface.to_s != zone
        unavailable << UnavailableCandidate.new(
          candidate: candidate,
          reason: "not assigned to the destination zone interface #{zone}")
      elsif outgoing_interface && candidate.interface != outgoing_interface
        unavailable << UnavailableCandidate.new(
          candidate: candidate,
          reason: "not on the outgoing interface #{outgoing_interface}")
      else
        available << candidate
      end
    end

    eliminations = []
    winner = available.first
    available.drop(1).each do |challenger|
      rule, prefer_challenger, reason =
        compare_source_candidates(winner, challenger, dest, dest_scope, dest_label, table,
                                  effective_interface, next_hop, prefer_temporary)
      loser = prefer_challenger ? winner : challenger
      eliminations << SourceElimination.new(
        candidate: loser,
        rule: rule,
        rule_name: rule && SOURCE_SELECTION_RULES[rule],
        reason: reason)
      winner = challenger if prefer_challenger
    end

    SourceSelection.new(destination: dest, winner: winner,
                        eliminations: eliminations, unavailable: unavailable)
  end

  # :stopdoc:

  def self.compile_policy_table(policy_table)
    policy_table.map do |entry|
      prefix = entry[:prefix]
      prefix = IPAddr.new(prefix) unless prefix.is_a?(IPAddr)
      [prefix, entry[:precedence], entry[:label]]
    end
  end
  private_class_method :compile_policy_table

  def self.policy_label(table, addr)
    # IPv4 addresses are looked up both natively and in their
    # IPv4-mapped form, so that entries such as ::ffff:0:0/96 apply.
    addrs = addr.ipv4? ? [addr, addr.ipv4_mapped] : [addr]
    best_length = -1
    best_label = nil
    table.each do |prefix, _precedence, label|
      addrs.each do |a|
        next unless prefix.family == a.family && prefix.include?(a)
        if prefix.prefix > best_length
          best_length = prefix.prefix
          best_label = label
        end
      end
    end
    best_label
  end
  private_class_method :policy_label

  def self.rfc6724_scope(addr)
    if addr.ipv4?
      i = addr.to_i
      return SCOPE_INTERFACE_LOCAL if i & 0xff000000 == 0x7f000000
      return SCOPE_LINK_LOCAL if i & 0xffff0000 == 0xa9fe0000
      SCOPE_GLOBAL
    else
      i = addr.to_i
      return SCOPE_INTERFACE_LOCAL if i == 1
      return (i >> 112) & 0xf if (i >> 120) == 0xff # multicast
      return SCOPE_LINK_LOCAL if (i >> 118) == 0x3fa # fe80::/10
      return SCOPE_SITE_LOCAL if (i >> 118) == 0x3fb # fec0::/10
      SCOPE_GLOBAL
    end
  end
  private_class_method :rfc6724_scope

  def self.source_family_compatible?(src, dest)
    src.family == dest.family || (dest.ipv4_mapped? && src.ipv4?)
  end
  private_class_method :source_family_compatible?

  def self.same_source_address?(candidate, dest)
    src = candidate.address
    return src.to_i == dest.to_i if src.family == dest.family
    dest.ipv4_mapped? && src.ipv4? && src.ipv4_mapped.to_i == dest.to_i
  end
  private_class_method :same_source_address?

  def self.common_prefix_length(candidate, dest)
    src = candidate.address
    if src.family == dest.family
      bits = src.ipv4? ? 32 : 128
      cap = candidate.prefix_length
      xor = src.to_i ^ dest.to_i
    elsif dest.ipv4_mapped? && src.ipv4?
      bits = 128
      cap = candidate.prefix_length + 96
      xor = src.ipv4_mapped.to_i ^ dest.to_i
    else
      return 0
    end
    common = xor.zero? ? bits : bits - xor.bit_length
    [common, cap].min
  end
  private_class_method :common_prefix_length

  # Compares two candidates with the RFC 6724 rules in order and
  # returns [rule_id, prefer_b, reason].  rule_id is nil when no rule
  # could distinguish the candidates.
  def self.compare_source_candidates(a, b, dest, dest_scope, dest_label, table,
                                     interface, next_hop, prefer_temporary)
    # Rule 1: Prefer same address.
    a_same = same_source_address?(a, dest)
    b_same = same_source_address?(b, dest)
    if a_same != b_same
      return ["1", b_same, "the other candidate is identical to the destination address"]
    end

    # Rule 2: Prefer appropriate scope.
    if a.scope != b.scope
      prefer_b =
        if a.scope < dest_scope && b.scope < dest_scope
          b.scope > a.scope
        elsif a.scope < dest_scope
          true
        elsif b.scope < dest_scope
          false
        else
          b.scope < a.scope
        end
      winner_scope, loser_scope = prefer_b ? [b.scope, a.scope] : [a.scope, b.scope]
      return ["2", prefer_b,
              "scope #{winner_scope} is more appropriate than scope #{loser_scope} " \
              "for destination scope #{dest_scope}"]
    end

    # Rule 3: Avoid deprecated addresses.
    if a.deprecated? != b.deprecated?
      return ["3", !b.deprecated?, "the losing candidate is a deprecated address"]
    end

    # Rule 4: Prefer home addresses.
    if a.home? != b.home?
      return ["4", b.home?, "a home address is preferred over a care-of address"]
    end

    # Rule 5: Prefer outgoing interface.
    if interface
      a_on = a.interface == interface
      b_on = b.interface == interface
      if a_on != b_on
        return ["5", b_on, "the losing candidate is not on the outgoing interface #{interface}"]
      end
    end

    # Rule 5.5: Prefer addresses in a prefix advertised by the next-hop.
    if next_hop
      a_advertised = !a.next_hop.nil? && a.next_hop == next_hop
      b_advertised = !b.next_hop.nil? && b.next_hop == next_hop
      if a_advertised != b_advertised
        return ["5.5", b_advertised,
                "the losing candidate's prefix was not advertised by the selected next-hop #{next_hop}"]
      end
    end

    # Rule 6: Prefer matching label.
    a_match = policy_label(table, a.address) == dest_label
    b_match = policy_label(table, b.address) == dest_label
    if a_match != b_match
      return ["6", b_match,
              "the losing candidate's policy label does not match the destination label #{dest_label.inspect}"]
    end

    # Rule 7: Prefer temporary addresses.
    if a.temporary? != b.temporary?
      prefer_b = prefer_temporary ? b.temporary? : !b.temporary?
      kind = prefer_temporary ? "temporary" : "public"
      return ["7", prefer_b, "a #{kind} address is preferred"]
    end

    # Rule 8: Use longest matching prefix.
    a_common = common_prefix_length(a, dest)
    b_common = common_prefix_length(b, dest)
    if a_common != b_common
      prefer_b = b_common > a_common
      winner_len, loser_len = prefer_b ? [b_common, a_common] : [a_common, b_common]
      return ["8", prefer_b,
              "common prefix with the destination is #{winner_len} bits versus #{loser_len} bits"]
    end

    [nil, false, "the candidates are indistinguishable under all RFC 6724 rules"]
  end
  private_class_method :compare_source_candidates

  # :startdoc:

  protected
  # :stopdoc:

  def begin_addr
    @addr & @mask_addr
  end

  def end_addr
    case @family
    when Socket::AF_INET
      @addr | (IN4MASK ^ @mask_addr)
    when Socket::AF_INET6
      @addr | (IN6MASK ^ @mask_addr)
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end
  #:startdoc:

  # Set +@addr+, the internal stored ip address, to given +addr+. The
  # parameter +addr+ is validated using the first +family+ member,
  # which is +Socket::AF_INET+ or +Socket::AF_INET6+.
  def set(addr, *family)
    case family[0] ? family[0] : @family
    when Socket::AF_INET
      if addr < 0 || addr > IN4MASK
        raise InvalidAddressError, "invalid address: #{addr}"
      end
    when Socket::AF_INET6
      if addr < 0 || addr > IN6MASK
        raise InvalidAddressError, "invalid address: #{addr}"
      end
    else
      raise AddressFamilyError, "unsupported address family"
    end
    @addr = addr
    if family[0]
      @family = family[0]
      if @family == Socket::AF_INET
        @mask_addr &= IN4MASK
      end
    end
    return self
  end

  # Set current netmask to given mask.
  def mask!(mask)
    case mask
    when String
      case mask
      when /\A(0|[1-9]+\d*)\z/
        prefixlen = mask.to_i
      when /\A\d+\z/
        raise InvalidPrefixError, "leading zeros in prefix"
      else
        m = IPAddr.new(mask)
        if m.family != @family
          raise InvalidPrefixError, "address family is not same"
        end
        @mask_addr = m.to_i
        n = @mask_addr ^ m.instance_variable_get(:@mask_addr)
        unless ((n + 1) & n).zero?
          raise InvalidPrefixError, "invalid mask #{mask}"
        end
        @addr &= @mask_addr
        return self
      end
    else
      prefixlen = mask
    end
    case @family
    when Socket::AF_INET
      if prefixlen < 0 || prefixlen > 32
        raise InvalidPrefixError, "invalid length"
      end
      masklen = 32 - prefixlen
      @mask_addr = ((IN4MASK >> masklen) << masklen)
    when Socket::AF_INET6
      if prefixlen < 0 || prefixlen > 128
        raise InvalidPrefixError, "invalid length"
      end
      masklen = 128 - prefixlen
      @mask_addr = ((IN6MASK >> masklen) << masklen)
    else
      raise AddressFamilyError, "unsupported address family"
    end
    @addr = ((@addr >> masklen) << masklen)
    return self
  end

  private

  # Creates a new ipaddr object either from a human readable IP
  # address representation in string, or from a packed in_addr value
  # followed by an address family.
  #
  # In the former case, the following are the valid formats that will
  # be recognized: "address", "address/prefixlen" and "address/mask",
  # where IPv6 address may be enclosed in square brackets (`[' and
  # `]').  If a prefixlen or a mask is specified, it returns a masked
  # IP address.  Although the address family is determined
  # automatically from a specified string, you can specify one
  # explicitly by the optional second argument.
  #
  # Otherwise an IP address is generated from a packed in_addr value
  # and an address family.
  #
  # The IPAddr class defines many methods and operators, and some of
  # those, such as &, |, include? and ==, accept a string, or a packed
  # in_addr value instead of an IPAddr object.
  def initialize(addr = '::', family = Socket::AF_UNSPEC)
    @mask_addr = nil
    if !addr.kind_of?(String)
      case family
      when Socket::AF_INET, Socket::AF_INET6
        set(addr.to_i, family)
        @mask_addr = (family == Socket::AF_INET) ? IN4MASK : IN6MASK
        return
      when Socket::AF_UNSPEC
        raise AddressFamilyError, "address family must be specified"
      else
        raise AddressFamilyError, "unsupported address family: #{family}"
      end
    end
    prefix, prefixlen = addr.split('/', 2)
    if prefix =~ /\A\[(.*)\]\z/i
      prefix = $1
      family = Socket::AF_INET6
    end
    if prefix =~ /\A(.*)(%\w+)\z/
      prefix = $1
      zone_id = $2
      family = Socket::AF_INET6
    end
    # It seems AI_NUMERICHOST doesn't do the job.
    #Socket.getaddrinfo(left, nil, Socket::AF_INET6, Socket::SOCK_STREAM, nil,
    #                  Socket::AI_NUMERICHOST)
    @addr = @family = nil
    if family == Socket::AF_UNSPEC || family == Socket::AF_INET
      @addr = in_addr(prefix)
      if @addr
        @family = Socket::AF_INET
      end
    end
    if !@addr && (family == Socket::AF_UNSPEC || family == Socket::AF_INET6)
      @addr = in6_addr(prefix)
      @family = Socket::AF_INET6
    end
    @zone_id = zone_id
    if family != Socket::AF_UNSPEC && @family != family
      raise AddressFamilyError, "address family mismatch"
    end
    if prefixlen
      mask!(prefixlen)
    else
      @mask_addr = (@family == Socket::AF_INET) ? IN4MASK : IN6MASK
    end
  end

  # :stopdoc:
  def coerce_other(other)
    case other
    when IPAddr
      other
    when String
      self.class.new(other)
    else
      self.class.new(other, @family)
    end
  end

  def in_addr(addr)
    case addr
    when Array
      octets = addr
    else
      RE_IPV4ADDRLIKE.match?(addr) or return nil
      octets = addr.split('.')
    end
    octets.inject(0) { |i, s|
      (n = s.to_i) < 256 or raise InvalidAddressError, "invalid address: #{addr}"
      (s != '0') && s.start_with?('0') and raise InvalidAddressError, "zero-filled number in IPv4 address is ambiguous: #{addr}"
      i << 8 | n
    }
  end

  def in6_addr(left)
    case left
    when RE_IPV6ADDRLIKE_FULL
      if $2
        addr = in_addr($~[2,4])
        left = $1 + ':'
      else
        addr = 0
      end
      right = ''
    when RE_IPV6ADDRLIKE_COMPRESSED
      if $4
        left.count(':') <= 6 or raise InvalidAddressError, "invalid address: #{left}"
        addr = in_addr($~[4,4])
        left = $1
        right = $3 + '0:0'
      else
        left.count(':') <= ($1.empty? || $2.empty? ? 8 : 7) or
          raise InvalidAddressError, "invalid address: #{left}"
        left = $1
        right = $2
        addr = 0
      end
    else
      raise InvalidAddressError, "invalid address: #{left}"
    end
    l = left.split(':')
    r = right.split(':')
    rest = 8 - l.size - r.size
    if rest < 0
      return nil
    end
    (l + Array.new(rest, '0') + r).inject(0) { |i, s|
      i << 16 | s.hex
    } | addr
  end

  def addr_mask(addr)
    case @family
    when Socket::AF_INET
      return addr & IN4MASK
    when Socket::AF_INET6
      return addr & IN6MASK
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end

  def _reverse
    case @family
    when Socket::AF_INET
      return (0..3).map { |i|
        (@addr >> (8 * i)) & 0xff
      }.join('.')
    when Socket::AF_INET6
      return ("%.32x" % @addr).reverse!.gsub!(/.(?!$)/, '\&.')
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end

  def _to_string(addr)
    case @family
    when Socket::AF_INET
      return (0..3).map { |i|
        (addr >> (24 - 8 * i)) & 0xff
      }.join('.')
    when Socket::AF_INET6
      return (("%.32x" % addr).gsub!(/.{4}(?!$)/, '\&:'))
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end

end

unless Socket.const_defined? :AF_INET6
  class Socket < BasicSocket
    # IPv6 protocol family
    AF_INET6 = Object.new.freeze
  end

  class << IPSocket
    private

    def valid_v6?(addr) # :nodoc:
      case addr
      when IPAddr::RE_IPV6ADDRLIKE_FULL
        if $2
          $~[2,4].all? {|i| i.to_i < 256 }
        else
          true
        end
      when IPAddr::RE_IPV6ADDRLIKE_COMPRESSED
        if $4
          addr.count(':') <= 6 && $~[4,4].all? {|i| i.to_i < 256}
        else
          addr.count(':') <= 7
        end
      else
        false
      end
    end

    alias getaddress_orig getaddress

    public

    # Returns a +String+ based representation of a valid DNS hostname,
    # IPv4 or IPv6 address.
    #
    #   IPSocket.getaddress 'localhost'         #=> "::1"
    #   IPSocket.getaddress 'broadcasthost'     #=> "255.255.255.255"
    #   IPSocket.getaddress 'www.ruby-lang.org' #=> "221.186.184.68"
    #   IPSocket.getaddress 'www.ccc.de'        #=> "2a00:1328:e102:ccc0::122"
    def getaddress(s)
      if valid_v6?(s)
        s
      else
        getaddress_orig(s)
      end
    end
  end
end
