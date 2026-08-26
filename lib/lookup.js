const dns = require('dns')

// `dns.lookup(host)` with no family returns whichever record the resolver
// prefers, and on a host where "localhost" carries both an A and an AAAA that
// is `::1`. Every peer this module could reach used to be IPv4, so an
// unconstrained answer arrived at a C side that parsed IPv4 only and was
// refused outright — the EINVAL that failed `connect with resolve` and hung
// `echo socket with resolve` on any machine whose resolver answered IPv6
// first. Now that both families parse, an unconstrained answer is worse than
// an error: the datagram leaves for `::1` and an IPv4 peer never sees it, with
// nothing reported to anyone.
//
// A dual-stack socket reaches an IPv4 destination through its v4-mapped form,
// so IPv4 is the answer that reaches the most peers and is preferred whenever
// the name carries one. IPv6 is used when the name carries nothing else, which
// is what makes an IPv6-only host reachable at all.
module.exports = function lookup (host, cb) {
  dns.lookup(host, { all: true }, function (err, addresses) {
    if (err) return cb(err)
    if (!addresses || !addresses.length) return cb(new Error('Could not resolve ' + host))

    let chosen = addresses[0]
    for (const address of addresses) {
      if (address.family === 4) {
        chosen = address
        break
      }
    }

    cb(null, chosen.address)
  })
}
