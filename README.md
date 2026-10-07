# IPAddr

IPAddr provides a set of methods to manipulate an IP address.  Both
IPv4 and IPv6 are supported.

[![build](https://github.com/ruby/ipaddr/actions/workflows/test.yml/badge.svg)](https://github.com/ruby/ipaddr/actions/workflows/test.yml)

## Installation

This library is part of the standard ruby distribution as default gem
and synchronized periodically, but you can explicitly depend on this
gem with version constraints as necessary, like when you need a newer
version than comes with older versions of ruby.

For example, you can add this line to your application's Gemfile:

```ruby
gem 'ipaddr', '~> 1.2'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ipaddr

## Usage

```ruby
require 'ipaddr'

ipaddr1 = IPAddr.new "3ffe:505:2::1"

p ipaddr1                   #=> #<IPAddr: IPv6:3ffe:0505:0002:0000:0000:0000:0000:0001/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff>

p ipaddr1.to_s              #=> "3ffe:505:2::1"

ipaddr2 = ipaddr1.mask(48)  #=> #<IPAddr: IPv6:3ffe:0505:0002:0000:0000:0000:0000:0000/ffff:ffff:ffff:0000:0000:0000:0000:0000>

p ipaddr2.to_s              #=> "3ffe:505:2::"

ipaddr3 = IPAddr.new "192.168.2.0/24"

p ipaddr3                   #=> #<IPAddr: IPv4:192.168.2.0/255.255.255.0>
```

## RFC 6724 source address selection

`IPAddr.select_source` simulates the RFC 6724 source address
selection algorithm offline.  Everything the algorithm needs is
passed explicitly (candidate attributes, outgoing interface, next
hop, policy table); the state of the machine running the code is
never consulted.

```ruby
require 'ipaddr'

result = IPAddr.select_source("2001:db8::1", [
  { address: "2001:db8::5", interface: "eth0", deprecated: true },
  { address: "2001:db8::9", interface: "eth0" },
])

result.winner.address.to_s        #=> "2001:db8::9"
result.eliminations.first.rule    #=> "3"
result.eliminations.first.reason  #=> "the losing candidate is a deprecated address"
```

Candidates are compared pairwise with the RFC 6724 rules in their
specified order (same address, appropriate scope, avoid deprecated,
prefer home, outgoing interface, next-hop advertised prefix, matching
label, temporary addresses, longest matching prefix); the first rule
that distinguishes two candidates decides between them.  The policy
table can be replaced with the `policy_table:` keyword (see
`IPAddr::DEFAULT_POLICY_TABLE` for the shape), and unknown route
information is expressed by simply omitting `next_hop:`.

## Alternative

The [ipaddress](https://rubygems.org/gems/ipaddress) gem is a popular,
extensive library for manipulating IP addresses with a layer of
compatibility with `ipaddr`.  If you need a richer set of features
than `ipaddr` has, try this library instead.

## Development

After checking out the repo, run `bundle install` to install dependencies. Then, run `rake test` to run the tests.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/ruby/ipaddr.

## License

The gem is available as open source under the terms of the [2-Clause BSD License](https://opensource.org/licenses/BSD-2-Clause).
