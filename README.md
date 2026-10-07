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

## Prefix-preserving anonymization (Crypto-PAn)

`IPAddr::CryptoPAn` implements the Crypto-PAn algorithm (Xu, Fan,
Ammar & Moon, ICNP 2002) for anonymizing IP addresses in logs while
keeping the length of the prefix two addresses share.  It uses a
32-byte key and AES (via the `openssl` library), supports both IPv4
and IPv6, is deterministic for a given key, and is fully invertible
with the same key.

```ruby
require 'ipaddr/crypto_pan'

key = Random.bytes(32)  # 16-byte AES key + 16-byte pad seed; keep it secret
cryptopan = IPAddr::CryptoPAn.new(key)

anon = cryptopan.anonymize('192.0.2.1')
cryptopan.deanonymize(anon)              #=> back to 192.0.2.1

cryptopan.anonymize_cidr('192.0.2.128/25')  # keeps the /25 mask, zeroes host bits
```

Contract notes:

- IPv4 and IPv6 are anonymized as independent namespaces; prefix
  relationships are only preserved within one address family.
  IPv4-mapped IPv6 addresses are treated as IPv6 (use `IPAddr#native`
  first if you want IPv4 semantics).
- Addresses with an IPv6 zone id (e.g. `fe80::1%eth0`) are rejected;
  split the scope zone off before anonymizing.
- The key never appears in `inspect`, error messages, or serialized
  output (serialization is refused).

**Warning:** prefix preservation is a property of the algorithm, not a
privacy guarantee.  By construction it reveals which anonymized
addresses share prefixes and for how long, so this must not be
presented as unlinkable anonymization.  Anyone holding the key can
reverse every mapping.

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
