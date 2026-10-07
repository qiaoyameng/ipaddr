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

  # In-memory RPKI route origin validation (RFC 6811). This namespace
  # accepts VRP payloads that have already had their signatures verified;
  # it does not download certificates or verify a certificate chain.
  module RPKI
    # The route is covered and at least one VRP authorizes it.
    VALID = :valid
    # The route is covered, but every covering VRP rejects it.
    INVALID = :invalid
    # No VRP covers the route.
    NOT_FOUND = :not_found

    # Raised for invalid RPKI input or query values.
    class ValidationError < Error; end
    # Raised when a VRP tuple has invalid prefix, maxLength, or ASN values.
    class InvalidVRPError < ValidationError; end

    # A validated route origin authorization: prefix, maxLength, and ASN.
    VRP = Struct.new(:prefix, :max_length, :asn)
    # A covering VRP and the reason it rejects a particular route.
    Rejection = Struct.new(:vrp, :reason, :message)

    # Outcome of validating one route prefix against one origin ASN.
    class Result
      attr_reader :status, :route_prefix, :origin_asn, :authorizations

      def initialize(status, route_prefix, origin_asn, authorizations, covering_nodes)
        @status = status
        @route_prefix = route_prefix
        @origin_asn = origin_asn
        @authorizations = authorizations
        @covering_nodes = covering_nodes
      end

      def valid?
        status == VALID
      end

      def invalid?
        status == INVALID
      end

      def not_found?
        status == NOT_FOUND
      end

      def code
        case status
        when VALID
          "Valid"
        when INVALID
          "Invalid"
        else
          "NotFound"
        end
      end

      alias to_s code

      def rejections
        @rejections ||= build_rejections.freeze
      end

      private

      def prefix_at(depth)
        address_length = route_prefix.ipv4? ? 32 : 128
        host_bits = address_length - depth
        mask = ((2**address_length - 1) >> host_bits) << host_bits
        IPAddr.new(route_prefix.to_i & mask, route_prefix.family).mask(depth).freeze
      end

      def build_rejections
        return [] if status == VALID

        @covering_nodes.flat_map { |depth, node|
          node.groups.flat_map { |asn, max_lengths|
            max_lengths.map { |max_length|
              next if asn == origin_asn && asn != 0 && max_length >= route_prefix.prefix

              if asn == 0
                reason = :as0
                message = "AS0 VRPs withdraw authorization and do not authorize a route origin"
              elsif asn == origin_asn
                reason = :prefix_length_exceeds_max_length
                message = "route prefix length #{route_prefix.prefix} exceeds maxLength #{max_length}"
              else
                reason = :origin_asn_mismatch
                message = "expected origin ASN #{asn}, got #{origin_asn}"
              end

              vrp = VRP.new(prefix_at(depth), max_length, asn).freeze
              Rejection.new(vrp, reason, message).freeze
            }
          }
        }.compact.sort_by { |rejection|
          [-rejection.vrp.prefix.prefix, rejection.vrp.asn, rejection.vrp.max_length]
        }
      end
    end

    # An immutable, published set of VRP indexes.
    class Version
      attr_reader :number, :ipv4_root, :ipv6_root, :authorization_count

      def self.empty(number = 0)
        new(number, Node.new.freeze, Node.new.freeze, 0).freeze
      end

      def self.build(number, vrps)
        unless vrps.respond_to?(:each)
          raise InvalidVRPError, "VRPs must be an enumerable collection"
        end

        ipv4_root = Node.new
        ipv6_root = Node.new
        validated_vrps = vrps.map { |raw_vrp| InputParser.vrp(raw_vrp) }
        authorization_count = 0

        validated_vrps.each { |vrp|
          root = vrp.prefix.ipv4? ? ipv4_root : ipv6_root
          authorization_count += 1 if root.add(
            vrp.prefix.to_i, vrp.prefix.prefix, vrp.max_length, vrp.asn,
            vrp.prefix.ipv4? ? 32 : 128
          )
        }

        new(number, ipv4_root.freeze, ipv6_root.freeze, authorization_count).freeze
      end

      def initialize(number, ipv4_root, ipv6_root, authorization_count)
        @number = number
        @ipv4_root = ipv4_root
        @ipv6_root = ipv6_root
        @authorization_count = authorization_count
      end

      def validate(route_prefix, origin_asn)
        root = route_prefix.ipv4? ? ipv4_root : ipv6_root
        route_length = route_prefix.prefix
        address = route_prefix.to_i
        address_length = route_prefix.ipv4? ? 32 : 128
        node = root
        covering_nodes = []

        0.upto(route_length) { |depth|
          covering_nodes << [depth, node] if node.groups

          break if depth == route_length

          bit = (address >> (address_length - depth - 1)) & 1
          child = node.children[bit]
          break unless child
          node = child
        }

        return Result.new(NOT_FOUND, route_prefix, origin_asn, [].freeze, [].freeze) if
          covering_nodes.empty?

        authorizations = covering_nodes.flat_map { |depth, covering_node|
          max_lengths = covering_node.groups[origin_asn]
          next [] if max_lengths.nil? || origin_asn.zero?

          max_lengths.select { |max_length|
            max_length >= route_length
          }.map { |max_length|
            VRP.new(prefix_at(route_prefix, depth), max_length, origin_asn).freeze
          }
        }.sort_by { |vrp|
          [-vrp.prefix.prefix, vrp.max_length]
        }

        status = authorizations.empty? ? INVALID : VALID
        Result.new(status, route_prefix, origin_asn,
                   authorizations.freeze, covering_nodes.freeze)
      end

      private

      def prefix_at(route_prefix, depth)
        address_length = route_prefix.ipv4? ? 32 : 128
        host_bits = address_length - depth
        mask = ((2**address_length - 1) >> host_bits) << host_bits
        IPAddr.new(route_prefix.to_i & mask, route_prefix.family).mask(depth).freeze
      end
    end

    # A query handle pinned to one immutable version.
    class Snapshot
      attr_reader :version

      def initialize(version)
        @version = version
      end

      def version_number
        @version.number
      end

      def validate(prefix, origin_asn)
        route_prefix, = InputParser.route(prefix)
        @version.validate(route_prefix, InputParser.asn(origin_asn))
      end
    end

    # An atomic in-memory VRP view.
    class View
      attr_reader :version

      def initialize(vrps = [])
        @mutex = Mutex.new
        @version = Version.empty
        replace(vrps)
      end

      def version_number
        @version.number
      end

      def authorization_count
        @version.authorization_count
      end

      # Parse and index every VRP before replacing the current version.
      def replace(vrps)
        @mutex.synchronize {
          @version = Version.build(@version.number + 1, vrps)
        }
        self
      end

      # Returns a snapshot that continues to see this version after updates.
      def snapshot
        Snapshot.new(@version)
      end

      def with_snapshot
        yield snapshot
      end

      def validate(prefix, origin_asn)
        route_prefix, = InputParser.route(prefix)
        @version.validate(route_prefix, InputParser.asn(origin_asn))
      end
    end

    # Binary prefix trie: a query follows at most 32 or 128 nodes.
    class Node
      attr_reader :children, :groups

      def initialize
        @children = [nil, nil]
        @groups = nil
      end

      def add(address, prefix_length, max_length, asn, address_length)
        node = self
        prefix_length.times { |depth|
          bit = (address >> (address_length - depth - 1)) & 1
          node.children[bit] ||= Node.new
          node = node.children[bit]
        }

        node.add_group(asn, max_length)
      end

      def add_group(asn, max_length)
        @groups ||= {}
        @groups[asn] ||= []
        unless @groups[asn].include?(max_length)
          @groups[asn] << max_length
          true
        else
          false
        end
      end

      def freeze
        children.each { |child| child.freeze if child }
        children.freeze
        if groups
          groups.each_pair { |asn, max_lengths|
            groups[asn] = max_lengths.sort.freeze
          }
          groups.freeze
        end
        super
      end
    end

    module InputParser
      module_function

      def vrp(input)
        prefix, max_length, asn = components(input)
        begin
          network, prefix_length = strict_prefix(prefix, "VRP prefix")
        rescue Error => error
          raise InvalidVRPError, error.message
        end
        max_length = integer(max_length, "maxLength")
        asn = asn(asn)
        maximum_length = network.ipv4? ? 32 : 128

        if max_length < prefix_length || max_length > maximum_length
          raise InvalidVRPError,
                "maxLength #{max_length} is outside #{prefix_length}..#{maximum_length}"
        end

        VRP.new(network, max_length, asn).freeze
      end

      def route(prefix)
        begin
          strict_prefix(prefix, "route prefix")
        rescue Error => error
          raise ValidationError, error.message
        end
      end

      def asn(value)
        unless value.is_a?(Integer) && (0..4_294_967_295).cover?(value)
          raise InvalidVRPError, "ASN must be an integer in 0..4294967295"
        end

        value
      end

      def components(input)
        case input
        when VRP
          [input.prefix, input.max_length, input.asn]
        when Array
          unless input.length == 3
            raise InvalidVRPError, "VRP array must contain prefix, maxLength, and ASN"
          end

          input
        when Hash
          [
            field(input, :prefix),
            field(input, :max_length, :maxLength),
            field(input, :asn, :ASN)
          ]
        else
          if input.respond_to?(:prefix) &&
             input.respond_to?(:max_length) &&
             input.respond_to?(:asn)
            [input.prefix, input.max_length, input.asn]
          else
            raise InvalidVRPError, "unsupported VRP: #{input.inspect}"
          end
        end
      end

      def field(hash, *keys)
        keys.each do |key|
          return hash[key] if hash.key?(key)

          string_key = key.to_s
          return hash[string_key] if hash.key?(string_key)
        end
        nil
      end

      def integer(value, name)
        unless value.is_a?(Integer)
          raise InvalidVRPError, "#{name} must be an integer"
        end

        value
      end

      def strict_prefix(value, label)
        case value
        when IPAddr
          network = value.clone
          masked = network.mask(network.prefix)
          unless masked.to_i == value.to_i
            raise InvalidPrefixError, "#{label} has host bits set: #{value.cidr}"
          end
          network = masked
        when String
          if value.include?("%")
            raise InvalidAddressError, "#{label} must not contain a zone identifier"
          end

          address, raw_length = value.split("/", 2)
          candidate = IPAddr.new(address)
          maximum_length = candidate.ipv4? ? 32 : 128
          length = raw_length ? parse_length(raw_length, maximum_length) : maximum_length
          network = candidate.mask(length)
          unless candidate.to_i == network.to_i
            raise InvalidPrefixError, "#{label} has host bits set: #{value}"
          end
        else
          raise InvalidPrefixError, "#{label} must be an IPAddr or prefix string"
        end

        if network.ipv6? && network.zone_id
          raise InvalidAddressError, "#{label} must not contain a zone identifier"
        end

        [network.freeze, network.prefix]
      end

      def parse_length(value, maximum)
        unless /\A(?:0|[1-9]\d*)\z/.match?(value)
          raise InvalidPrefixError, "invalid prefix length: #{value.inspect}"
        end

        length = value.to_i
        unless length >= 0 && length <= maximum
          raise InvalidPrefixError, "prefix length #{length} is outside 0..#{maximum}"
        end

        length
      end
    end

    private_constant :InputParser, :Node, :Version
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
