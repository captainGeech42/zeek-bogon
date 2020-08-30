# Zeek Bogon Networks Package

This package adds two fields to Zeek's `conn.log` to identify if an orig/resp IP is in a bogon network range:

* `bogon_orig`
* `bogon_resp`

Network ranges that will be marked as bogon:

* `0.0.0.0/8`
* `127.0.0.0/8`
* `169.254.0.0/16`
* `192.0.2.0/24`
* `198.51.100.0/24`
* `203.0.113.0/24`
* `224.0.0.0/4`
* `255.255.255.255/32`
* `::1/128`
* `100::/64`
* `2001:db8::/32`
* `fe80::/10`
* `ff00::/8`

This package also can classify the [RFC 1918 private address space](https://tools.ietf.org/html/rfc1918#section-3) and [RFC 4193 IPv6 Unicast Addresses](https://tools.ietf.org/html/rfc4193#section-3) if desired. This functionality is disabled by default, as many Zeek users run Zeek on a local network where RFC 1918 traffic is expected.

To enable classifying RFC 1918/4193 private address space, add the following to your `local.zeek`:

```zeek
redef Bogon::private_as_bogon = T;
```

This will mark these ranges as bogon:

* `10.0.0.0/8`
* `172.16.0.0/12`
* `192.168.0.0/16`
* `fc00::/7`

## Links

For more info on bogon ranges, please see the following:

* [Bad Packets: Hunting for bogons and the ISPs that announce them](https://badpackets.net/hunting-for-bogons-and-the-isps-that-announce-them/)
* [Wikipedia: Bogon filtering](https://en.wikipedia.org/wiki/Bogon_filtering)
* [Team Cymru: The Bogon Reference](https://team-cymru.com/community-services/bogon-reference/)