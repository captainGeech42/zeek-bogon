# Zeek Bogon Networks Package

This package adds two fields to Zeek's `conn.log` to identify if an IP is in a bogon network range.

Network ranges currently classified as bogon:
* `0.0.0.0/8`
* `10.0.0.0/8`
* `100.64.0.0/10`
* `127.0.0.0/8`
* `169.254.0.0/16`
* `172.167.0.0/12`
* `192.168.0.0/16`
* `224.0.0.0/4`

This package also can classify the [RFC 1918 private address space](https://tools.ietf.org/html/rfc1918#section-3) if desired. This functionality is disabled by default, as many Zeek users run Zeek on a local network where RFC 1918 traffic is expected.

To enable classifying RFC 1918 private address space, add the following to your `local.zeek`:

```zeek
redef Bogon::RFC1918_as_bogon = T;
```

## Links

For more info on bogon ranges, please see the following:

* [Bad Packets: Hunting for bogons and the ISPs that announce them](https://badpackets.net/hunting-for-bogons-and-the-isps-that-announce-them/)
* [Wikipedia: Bogon filtering](https://en.wikipedia.org/wiki/Bogon_filtering)