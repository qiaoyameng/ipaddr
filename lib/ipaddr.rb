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

  # Raised when RFC 6724 source address selection has no usable candidate.
  class SourceAddressSelectionError < Error; end

  SCOPE_NODE = 1
  SCOPE_LINK = 2
  SCOPE_REALM = 3
  SCOPE_ADMIN = 4
  SCOPE_SITE = 5
  SCOPE_ORGANIZATION = 8
  SCOPE_GLOBAL = 14

  # A locally assigned address considered as an RFC 6724 source address
  # candidate.  All interface and address-state information is supplied
  # explicitly; IPAddr never inspects the operating system.
  class SourceAddress
    attr_reader :address, :interface, :scope, :prefix

    def initialize(address, interface: nil, scope: SCOPE_GLOBAL,
                   deprecated: false, temporary: false, home: false,
                   prefix: nil)
      if address.is_a?(String) && address.include?('/')
        address_part, prefix_part = address.split('/', 2)
        address_part = address_part.sub(/\A\[/, '').sub(/\]\z/, '')
        address = IPAddr.new(address_part)
        prefix ||= prefix_part
      else
        address = IPAddr.new(address)
      end

      @address = address
      @interface = SourceAddressSelector.normalize_interface(
        interface || (address.ipv6? ? address.zone_id : nil)
      )
      @scope = SourceAddressSelector.scope_rank(scope)
      @deprecated = !!deprecated
      @temporary = !!temporary
      @home = !!home

      prefix = prefix.is_a?(String) ? prefix.to_i : prefix
      @prefix = prefix || address.prefix
      maximum_prefix = address.ipv4? ? 32 : 128
      unless @prefix.is_a?(Integer) && @prefix >= 0 && @prefix <= maximum_prefix
        raise InvalidPrefixError, "invalid prefix: #{@prefix.inspect}"
      end
    end

    def deprecated?
      @deprecated
    end

    def temporary?
      @temporary
    end

    def home?
      @home
    end

    def to_s
      interface ? "#{address}%#{interface}" : address.to_s
    end

    def inspect
      "#<#{self.class}: #{to_s} scope=#{scope} prefix=#{prefix}" \
        "#{' deprecated' if deprecated?}#{' temporary' if temporary?}" \
        "#{' home' if home?}>"
    end

    def ==(other)
      other.is_a?(SourceAddress) &&
        address == other.address &&
        interface == other.interface &&
        scope == other.scope &&
        prefix == other.prefix &&
        deprecated? == other.deprecated? &&
        temporary? == other.temporary? &&
        home? == other.home?
    end
    alias eql? ==

    def hash
      [address, interface, scope, prefix, deprecated?, temporary?, home?].hash
    end
  end
  SourceAddressCandidate = SourceAddress

  # Why a candidate lost, or why it was not eligible.
  class SourceAddressElimination
    attr_reader :candidate, :rule, :reason, :matched_prefix

    def initialize(candidate, rule, reason, matched_prefix = nil)
      @candidate = candidate
      @rule = rule
      @reason = reason
      @matched_prefix = matched_prefix
    end

    def tied?
      rule.nil?
    end
  end

  # The selected RFC 6724 source address and first-rule explanations.
  class SourceAddressSelection
    attr_reader :candidate, :eliminations, :unavailable

    def initialize(candidate, eliminations, unavailable)
      @candidate = candidate
      @eliminations = eliminations
      @unavailable = unavailable
    end

    alias source_address candidate
    alias selected candidate
    alias eliminated eliminations

    def first_elimination
      eliminations.find { |elimination| !elimination.tied? }
    end

    def rule
      elimination = first_elimination
      elimination ? elimination.rule : (eliminations.empty? ? nil : :tie)
    end

    def reason
      elimination = first_elimination
      elimination ? elimination.reason : (eliminations.empty? ? nil : :tie)
    end

    def to_a
      [candidate, reason]
    end

    def to_ary
      to_a
    end

    def to_h
      {
        candidate: candidate,
        rule: rule,
        reason: reason,
        eliminations: eliminations,
        unavailable: unavailable
      }
    end
  end

  # Performs offline RFC 6724 source address selection.
  class SourceAddressSelector
    SCOPE_ALIASES = {
      node: SCOPE_NODE,
      node_local: SCOPE_NODE,
      interface: SCOPE_NODE,
      link: SCOPE_LINK,
      link_local: SCOPE_LINK,
      realm: SCOPE_REALM,
      realm_local: SCOPE_REALM,
      admin: SCOPE_ADMIN,
      administrative: SCOPE_ADMIN,
      site: SCOPE_SITE,
      site_local: SCOPE_SITE,
      organization: SCOPE_ORGANIZATION,
      global: SCOPE_GLOBAL
    }.freeze

    def self.normalize_interface(interface)
      case interface
      when nil
        nil
      when Symbol
        interface.to_s
      when Integer
        interface
      when String
        value = interface.sub(/\A%/, '')
        value.match?(/\A\d+\z/) ? value.to_i : value
      else
        interface.to_str.sub(/\A%/, '')
      end
    end

    def self.scope_rank(scope)
      case scope
      when Integer
        unless scope >= 0 && scope <= 15
          raise InvalidAddressError, "invalid scope: #{scope.inspect}"
        end
        scope
      when Symbol, String
        name = scope.to_s.tr('-', '_').downcase.to_sym
        SCOPE_ALIASES.fetch(name) do
          raise InvalidAddressError, "unknown scope: #{scope.inspect}"
        end
      else
        raise InvalidAddressError, "invalid scope: #{scope.inspect}"
      end
    end

    def initialize(destination, policy_table:, destination_scope: nil,
                   scope: nil, outgoing_interface: nil,
                   egress_interface: nil)
      @destination = IPAddr.new(destination)
      @outgoing_interface = self.class.normalize_interface(
        outgoing_interface || egress_interface
      )
      @destination_zone = self.class.normalize_interface(
        @destination.ipv6? ? @destination.zone_id : nil
      )
      @destination_scope = self.class.scope_rank(
        destination_scope || scope || infer_scope(@destination)
      )

      if @destination_zone && @outgoing_interface &&
          @destination_zone != @outgoing_interface
        raise SourceAddressSelectionError,
              "destination zone #{@destination_zone.inspect} does not match outgoing interface #{@outgoing_interface.inspect}"
      end

      @policy_entries = build_policy_entries(policy_table)
      @destination_label = label_for(@destination)
    end

    def select(candidates)
      available = []
      unavailable = []

      Array(candidates).each do |candidate|
        candidate = coerce_candidate(candidate)
        reason = unavailable_reason(candidate)
        if reason
          unavailable << SourceAddressElimination.new(candidate, nil, reason)
        else
          available << [candidate, label_for(candidate.address)]
        end
      end

      if available.empty?
        raise SourceAddressSelectionError, "no usable source address for #{@destination}"
      end

      winner, = available.first
      eliminations = []

      available[1..-1].each do |candidate, label|
        side, _reason = compare(winner, candidate, label)
        if side == :candidate
          winner = candidate
        end
      end

      available.each do |candidate, label|
        next if candidate.equal?(winner)

        _side, reason = compare(winner, candidate, label)
        rule = rule_for_reason(reason)
        eliminations << SourceAddressElimination.new(
          candidate, rule, reason,
          reason == :longer_prefix ?
            [common_prefix(winner), common_prefix(candidate)].max : nil
        )
      end

      SourceAddressSelection.new(winner, eliminations, unavailable)
    end

    private

    def coerce_candidate(candidate)
      case candidate
      when SourceAddress
        candidate
      when Hash
        address = candidate[:address] || candidate['address']
        if address.nil?
          raise InvalidAddressError, "source address candidate must have an address"
        end

        options = {}
        [
          :interface, :scope, :deprecated, :temporary, :home, :prefix
        ].each do |key|
          if candidate.key?(key) || candidate.key?(key.to_s)
            options[key] = candidate.key?(key) ? candidate[key] : candidate[key.to_s]
          end
        end
        SourceAddress.new(address, **options)
      else
        SourceAddress.new(candidate)
      end
    end

    def unavailable_reason(candidate)
      if candidate.address.family != @destination.family
        return :address_family_mismatch
      end

      required_interface = @outgoing_interface || @destination_zone
      if required_interface && candidate.interface != required_interface
        return @destination_zone && candidate.interface != @destination_zone ?
          :destination_zone_mismatch : :outgoing_interface_mismatch
      end

      nil
    end

    def compare(current, candidate, candidate_label)
      current_label = label_for(current.address)

      if current.scope == @destination_scope
        return [:current, :scope_mismatch] unless candidate.scope == @destination_scope
      elsif candidate.scope == @destination_scope
        return [:candidate, :scope_mismatch]
      elsif candidate.scope < current.scope
        return [:candidate, :wider_scope]
      elsif candidate.scope > current.scope
        return [:current, :wider_scope]
      end

      if current.deprecated? != candidate.deprecated?
        return candidate.deprecated? ?
          [:current, :deprecated] : [:candidate, :deprecated]
      end

      if current.home? != candidate.home?
        return candidate.home? ?
          [:candidate, :not_home] : [:current, :not_home]
      end

      if current_label == @destination_label
        return [:current, :label_mismatch] unless candidate_label == @destination_label
      elsif candidate_label == @destination_label
        return [:candidate, :label_mismatch]
      end

      if !current.home? && !candidate.home? &&
          current.temporary? != candidate.temporary?
        return candidate.temporary? ?
          [:candidate, :not_temporary] : [:current, :not_temporary]
      end

      current_prefix = common_prefix(current)
      candidate_prefix = common_prefix(candidate)
      if current_prefix != candidate_prefix
        return candidate_prefix > current_prefix ?
          [:candidate, :longer_prefix] : [:current, :longer_prefix]
      end

      [nil, :tie]
    end

    def rule_for_reason(reason)
      {
        scope_mismatch: 2,
        wider_scope: 2,
        deprecated: 3,
        not_home: 4,
        label_mismatch: 6,
        not_temporary: 7,
        longer_prefix: 8,
        tie: nil
      }.fetch(reason)
    end

    def common_prefix(candidate)
      length = @destination.ipv4? ? 32 : 128
      current = candidate.address.to_i
      destination = @destination.to_i

      length.times do |index|
        shift = length - index - 1
        if ((current >> shift) & 1) != ((destination >> shift) & 1)
          return [index, candidate.prefix].min
        end
      end

      [length, candidate.prefix].min
    end

    def build_policy_entries(policy_table)
      unless policy_table.respond_to?(:each)
        raise InvalidAddressError, "policy table must respond to each"
      end

      entries = []
      policy_table.each do |key, value = nil|
        if key.is_a?(Array)
          prefix, label = key
        elsif key.is_a?(Hash)
          prefix = key[:prefix] || key[:address] || key['prefix'] || key['address']
          label = key[:label] || key['label']
        else
          prefix = key
          label = value
        end

        if label.nil? && value.is_a?(Hash)
          label = value[:label] || value['label']
        end
        if label.nil? && value.is_a?(Array)
          label = value.last
        end
        if label.nil?
          raise InvalidAddressError, "policy entry #{prefix.inspect} has no label"
        end

        network = IPAddr.new(prefix)
        entries << [network, label]
      end

      entries.sort_by { |network, _| -network.prefix }
    end

    def label_for(address)
      _network, label = @policy_entries.find do |network, _label|
        network.family == address.family && network.include?(address)
      end

      unless label
        raise SourceAddressSelectionError,
              "no policy label for #{address}"
      end

      label
    end

    def infer_scope(address)
      if address.loopback?
        SCOPE_NODE
      elsif address.link_local?
        SCOPE_LINK
      elsif address.ipv6? && address.multicast?
        address.to_i & 0xf
      else
        SCOPE_GLOBAL
      end
    end
  end

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

  # Selects a source address for +destination+ using the rules in RFC 6724.
  # +candidates+ may contain IPAddr::SourceAddress objects, plain addresses, or
  # hashes of candidate attributes.  +policy_table+ maps address prefixes to
  # policy labels.  +destination_scope+ and +outgoing_interface+ are supplied
  # explicitly; the operating system is never consulted.
  # See IPAddr::SourceAddressSelector for the available options.
  def self.select_source_address(destination, candidates, **options)
    SourceAddressSelector.new(destination, **options).select(candidates)
  end

  # Selects this address as the destination of RFC 6724 source address
  # selection.
  def select_source_address(candidates, **options)
    self.class.select_source_address(self, candidates, **options)
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
