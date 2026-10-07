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

## Crypto-PAn address anonymization

IPAddr bundles an implementation of
[Crypto-PAn](https://en.wikipedia.org/wiki/IP_address_anonymization#Crypto-PAn),
a prefix-preserving IP address anonymization algorithm (Xu, Fan, Ammar
and Moon, ICNP 2002).  It hides the real addresses while keeping the
length of the prefix shared by any two addresses, which is useful for
publishing flow or firewall logs while retaining network structure.

The transform uses a 32-byte key: the first 16 bytes are the AES-128
key and the last 16 bytes are the algorithm's 128-bit padding block.
It is implemented on top of Ruby's OpenSSL and supports both IPv4 and
IPv6.

```ruby
require 'ipaddr'
require 'ipaddr/crypto_pan'

key = SecureRandom.bytes(32)
anonymizer = IPAddr::CryptoPAn.new(key)

anonymizer.anonymize("192.168.1.1")        #=> #<IPAddr: IPv4:208.23.87.35/...>
anonymizer.anonymize("2001:db8::1")       #=> #<IPAddr: IPv6:...>

# Deterministic and reversible with the same key.
anonymizer.deanonymize(anonymizer.anonymize("192.168.1.1")).to_s
#=> "192.168.1.1"
```

The same entry points accept single addresses and CIDR networks; a
network keeps its prefix length and the result is normalized to the
network address (host bits cleared):

```ruby
anonymizer.anonymize("192.168.0.1/24")    #=> #<IPAddr: IPv4:208.23.86.0/255.255.255.0>
anonymizer.anonymize("2001:db8::1/32")    #=> #<IPAddr: IPv6:dca:fbd7::/ffff:ffff::>
```

The address family and the network prefix length are preserved.  A
scoped IPv6 address (one with a zone identifier such as `fe80::1%eth0`)
is rejected with `IPAddr::InvalidAddressError`: the zone is not part of
the address bits, so callers must separate the scope before anonymizing
and re-attach it afterwards if needed.

### Reference vectors

For the key (hex)
`00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f`,
`anonymize` produces:

| Input | Anonymized |
| --- | --- |
| `0.0.0.0` | `39.159.183.74` |
| `127.0.0.1` | `78.169.18.48` |
| `192.168.1.1` | `208.23.87.35` |
| `10.0.0.1` | `44.58.126.168` |
| `1.2.3.4` | `38.93.85.28` |
| `255.255.255.255` | `246.77.4.11` |
| `::` | `279f:b74a:7572:135e:8f9b:8ef6:d1ee:e003` |
| `::1` | `279f:b74a:7572:135e:8f9b:8ef6:d1ee:e002` |
| `2001:db8::1` | `dca:fbd7:c523:eec4:9111:eca3:65ce:85d1` |
| `fe80::1` | `f706:8bab:511d:163e:23b:eb:66e0:d898` |

### Security considerations

Prefix preservation is a privacy leak, not a privacy feature: the
anonymized data still reveals which addresses belonged to the same
network, so an observer can infer topology, shared providers, and
clustering.  **Do not describe Crypto-PAn output as unlinkable or
relationship-hiding anonymization.**  In addition, anyone who obtains
the key (both halves of it) can fully reverse the mapping, so protect
the key as a secret.  `IPAddr::CryptoPAn` never exposes the key through
`#inspect`, exception messages, or (de)serialization.

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
