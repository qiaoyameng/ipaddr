# frozen_string_literal: true

require 'test/unit'
require 'ipaddr'
require 'set'

class TC_RPKI < Test::Unit::TestCase
  def test_valid_invalid_and_not_found
    view = IPAddr::RPKI::OriginView.new([
      ["192.0.2.0/24", 24, 64496]
    ])

    valid = view.lookup("192.0.2.0/24", 64496)
    assert_equal(IPAddr::RPKI::VALID, valid.status)
    assert_predicate(valid, :valid?)
    assert_equal([["192.0.2.0/24", 24, 64496]], vrp_tuples(valid.authorizations))
    assert_empty(valid.rejections)

    invalid = view.lookup("192.0.2.0/24", 64497)
    assert_equal(IPAddr::RPKI::INVALID, invalid.status)
    assert_predicate(invalid, :invalid?)
    assert_empty(invalid.authorizations)
    assert_equal([:asn_mismatch], invalid.rejections.map(&:reason))
    assert_equal([["192.0.2.0/24", 24, 64496]],
                 vrp_tuples(invalid.deciding_vrps))

    not_found = view.lookup("198.51.100.0/24", 64496)
    assert_equal(IPAddr::RPKI::NOT_FOUND, not_found.status)
    assert_predicate(not_found, :not_found?)
    assert_empty(not_found.deciding_vrps)
  end

  def test_max_length_boundary
    view = IPAddr::RPKI::OriginView.new([
      ["192.0.2.0/24", 26, 64496]
    ])

    assert_predicate(view.lookup("192.0.2.0/24", 64496), :valid?)
    assert_predicate(view.lookup("192.0.2.0/26", 64496), :valid?)
    assert_predicate(view.lookup("192.0.2.0/27", 64497), :not_found?)
  end

  def test_multiple_authorizations
    view = IPAddr::RPKI::OriginView.new([
      ["192.0.2.0/24", 24, 64496],
      ["192.0.2.0/24", 25, 64497],
      ["192.0.2.0/25", 25, 64496],
      ["192.0.2.0/23", 25, 64498]
    ])

    result = view.lookup("192.0.2.0/25", 64497)
    assert_predicate(result, :valid?)
    assert_equal(
      [["192.0.2.0/24", 25, 64497]],
      vrp_tuples(result.authorizations)
    )
    assert_empty(result.rejections)
    assert_equal(1, result.deciding_vrps.length)
  end

  def test_same_prefix_multiple_authorizations
    view = IPAddr::RPKI::OriginView.new([
      ["192.0.2.0/24", 25, 64496],
      ["192.0.2.0/24", 25, 64497]
    ])

    result_64496 = view.lookup("192.0.2.0/25", 64496)
    assert_predicate(result_64496, :valid?)
    assert_equal([64496], result_64496.authorizations.map(&:asn))

    result_64497 = view.lookup("192.0.2.0/25", 64497)
    assert_predicate(result_64497, :valid?)
    assert_equal([64497], result_64497.authorizations.map(&:asn))

    rejected = view.lookup("192.0.2.0/25", 64498)
    assert_predicate(rejected, :invalid?)
    assert_equal([64496, 64497], rejected.rejections.map { |item| item.vrp.asn })
  end

  def test_as0
    view = IPAddr::RPKI::OriginView.new([
      ["192.0.2.0/24", 24, 0],
      ["192.0.2.0/24", 24, 64496],
      ["198.51.100.0/24", 24, 64496]
    ])

    assert_equal([:as0_vrp, :asn_mismatch],
                 view.lookup("192.0.2.0/24", 64497).rejections.map(&:reason))
    assert_predicate(view.lookup("192.0.2.0/24", 64496), :valid?)
    assert_equal([:as0_vrp, :as0_origin],
                 view.lookup("192.0.2.0/24", 0).rejections.map(&:reason))
    assert_predicate(view.lookup("198.51.100.0/24", 0), :invalid?)
    assert_equal([:as0_origin], view.lookup("198.51.100.0/24", 0).rejections.map(&:reason))
    assert_predicate(view.lookup("203.0.113.0/24", 0), :not_found?)
  end

  def test_ipv4_and_ipv6_are_separate
    view = IPAddr::RPKI::OriginView.new([
      ["192.0.2.0/24", 24, 64496],
      ["2001:db8::/32", 48, 64497]
    ])

    assert_predicate(view.lookup("192.0.2.0/24", 64496), :valid?)
    assert_predicate(view.lookup("2001:db9::/32", 64496), :not_found?)
    assert_predicate(view.lookup("2001:db8::/48", 64497), :valid?)
  end

  def test_invalid_max_length
    assert_invalid_vrp("192.0.2.0/24", 23, 64496)
    assert_invalid_vrp("192.0.2.0/24", 33, 64496)
    assert_invalid_vrp("2001:db8::/32", 31, 64496)
    assert_invalid_vrp("2001:db8::/32", 129, 64496)
    assert_invalid_vrp("192.0.2.0/24", "24", 64496)
  end

  def test_invalid_asn
    assert_raise(IPAddr::RPKI::InvalidVRPError) do
      IPAddr::RPKI::VRP.new("192.0.2.0/24", 24, -1)
    end
    assert_raise(IPAddr::RPKI::InvalidVRPError) do
      IPAddr::RPKI::VRP.new("192.0.2.0/24", 24, 2**32)
    end

    view = IPAddr::RPKI::OriginView.new
    assert_raise(IPAddr::RPKI::InvalidQueryError) do
      view.lookup("192.0.2.0/24", -1)
    end
  end

  def test_batch_replacement_validates_before_publishing
    view = IPAddr::RPKI::OriginView.new([
      ["192.0.2.0/24", 24, 64496]
    ])
    old_snapshot = view.snapshot

    assert_raise(IPAddr::RPKI::InvalidVRPError) do
      view.replace([
        ["198.51.100.0/24", 24, 64497],
        ["203.0.113.0/24", 33, 64498]
      ])
    end

    assert_same(old_snapshot, view.snapshot)
    assert_equal(0, view.version)
    assert_predicate(view.lookup("192.0.2.0/24", 64496), :valid?)
    assert_predicate(view.lookup("198.51.100.0/24", 64497), :not_found?)
  end

  def test_published_snapshot_is_stable
    view = IPAddr::RPKI::OriginView.new
    assert_equal(0, view.version)
    view.replace([["192.0.2.0/24", 24, 64496]])
    snapshot = view.snapshot

    view.update(add: [["198.51.100.0/24", 24, 64497]])

    assert_equal(1, snapshot.version)
    assert_predicate(snapshot.lookup("198.51.100.0/24", 64497), :not_found?)
    assert_equal(2, view.version)
    assert_predicate(view.lookup("198.51.100.0/24", 64497), :valid?)
  end

  def test_incremental_update_and_duplicates
    view = IPAddr::RPKI::OriginView.new([
      ["192.0.2.0/24", 24, 64496],
      ["192.0.2.0/24", 24, 64496]
    ])
    assert_equal(1, view.snapshot.vrps.length)

    view.update(
      add: [
        ["192.0.2.0/24", 26, 64497],
        {prefix: "198.51.100.0/24", maxLength: 24, asn: 64498}
      ],
      remove: [["192.0.2.0/24", 24, 64496]]
    )

    assert_predicate(view.lookup("192.0.2.0/26", 64497), :valid?)
    assert_predicate(view.lookup("192.0.2.0/27", 64496), :not_found?)
    assert_predicate(view.lookup("198.51.100.0/24", 64498), :valid?)
  end

  def test_update_rejects_add_and_remove_conflict
    view = IPAddr::RPKI::OriginView.new
    tuple = ["192.0.2.0/24", 24, 64496]

    assert_raise(IPAddr::RPKI::InvalidVRPError) do
      view.update(add: [tuple], remove: [tuple])
    end
    assert_equal(0, view.version)
    assert_empty(view.snapshot.vrps)
  end

  def test_prefix_host_bits_are_canonicalized
    vrp = IPAddr::RPKI::VRP.new("192.0.2.127/24", 24, 64496)
    assert_equal("192.0.2.0/24", vrp.cidr)
    assert(vrp.frozen?)

    view = IPAddr::RPKI::OriginView.new([vrp])
    assert_predicate(view.lookup("192.0.2.0/24", 64496), :valid?)
  end

  def test_small_address_domain_exhaustion
    fixed_vrps = [
      ["192.0.2.0/30", 32, 64496],
      ["192.0.2.0/30", 32, 0]
    ]
    candidates = [
      ["192.0.2.0/31", 31],
      ["192.0.2.0/31", 32],
      ["192.0.2.0/32", 32],
      ["192.0.2.1/32", 32]
    ].product([64496, 64497]).map { |(prefix, max_length), asn| [prefix, max_length, asn] }
    routes = ["192.0.2.0/31", "192.0.2.0/32", "192.0.2.1/32"]
    origins = [64496, 64497, 64498]

    0.upto(candidates.length) do |count|
      candidates.combination(count).each do |selected|
        tuples = fixed_vrps + selected
        view = IPAddr::RPKI::OriginView.new(tuples)

        routes.each do |route|
          origins.each do |origin|
            expected = naive_lookup(tuples, route, origin)
            actual = view.lookup(route, origin)

            assert_equal(expected[:status], actual.status,
                         "#{route} AS#{origin} with #{tuples.inspect}")
            assert_equal(expected[:authorizations],
                         Set.new(vrp_tuples(actual.authorizations)),
                         route)
            assert_equal(expected[:rejections],
                         Set.new(actual.rejections.map { |rejection|
                           [tuple_for(rejection.vrp), rejection.reason]
                         }),
                         route)
          end
        end
      end
    end
  end

  private

  def assert_invalid_vrp(prefix, max_length, asn)
    assert_raise(IPAddr::RPKI::InvalidVRPError) do
      IPAddr::RPKI::VRP.new(prefix, max_length, asn)
    end
  end

  def vrp_tuples(vrps)
    vrps.map { |vrp| tuple_for(vrp) }
  end

  def tuple_for(vrp)
    [vrp.cidr, vrp.max_length, vrp.asn]
  end

  def naive_lookup(tuples, route, origin)
    route_prefix = IPAddr.new(route)
    covering = tuples.select do |prefix, max_length, _asn|
      IPAddr.new(prefix).include?(route_prefix) && max_length >= route_prefix.prefix
    end
    authorizations = covering.select { |_prefix, _max_length, asn| asn == origin && !asn.zero? }
    rejections = covering.map do |prefix, max_length, asn|
      reason =
        if asn.zero?
          :as0_vrp
        elsif origin.zero?
          :as0_origin
        else
          :asn_mismatch
        end
      [[prefix, max_length, asn], reason]
    end.reject { |tuple, _reason| authorizations.include?(tuple) }

    if authorizations.any?
      {status: IPAddr::RPKI::VALID, authorizations: Set.new(authorizations), rejections: Set.new}
    elsif rejections.any?
      {status: IPAddr::RPKI::INVALID, authorizations: Set.new, rejections: Set.new(rejections)}
    else
      {status: IPAddr::RPKI::NOT_FOUND, authorizations: Set.new, rejections: Set.new}
    end
  end
end
