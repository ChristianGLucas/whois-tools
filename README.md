# whois-tools

Composable Axiom nodes for deterministic parsing of domain and IP
registration records: legacy WHOIS text and RDAP JSON (RFC 9083, the IETF
successor protocol) into a single normalized shape.

Built for the [Axiom](https://axiom.dev) marketplace, handle
`christiangeorgelucas`.

## What it does

Every node is a pure text/JSON → struct transform. The caller supplies a
WHOIS response (as returned by a WHOIS server on port 43, or a caller's own
WHOIS client) or an RDAP response (as returned by a registry/registrar RDAP
HTTP endpoint) — this package never performs the network query or fetch
itself.

- **ParseWhois** — legacy WHOIS text → `RegistrationRecord` (registrar,
  registrant/admin/tech/billing contacts, name servers, DNSSEC,
  created/updated/expiration dates, normalized EPP status codes). Wraps
  [likexian/whois-parser](https://github.com/likexian/whois-parser)
  (Apache-2.0), which recognizes the free-text formats of hundreds of TLD
  registries.
- **ParseRdapDomain** — RDAP domain-object JSON (RFC 9083 §5.3) → the same
  `RegistrationRecord` shape, so downstream flows can treat a record
  identically regardless of source.
- **ParseRdapIpNetwork** — RDAP "ip network" JSON (RFC 9083 §5.4) →
  `IpRegistrationRecord` (handle, address range, CIDR blocks, allocation
  type, entities).
- **ParseRdapEntity** — a single RDAP "entity" object (RFC 9083 §5.1),
  including its jCard (RFC 7095) vCard array, → `Contact`.
- **NormalizeEppStatus** — one raw status token (bare EPP word, WHOIS
  "Domain Status:" line, or RDAP `epp#` URL) → the ICANN EPP status
  vocabulary: code, description, category, client/server.
- **ExtractKeyFacts** — flattens a parsed record to domain name, registrar,
  expiration date, and name servers, with optional deterministic
  days-until-expiry given a caller-supplied reference date.
- **DetectFormat** — heuristically classifies unknown text as `whois`,
  `rdap`, or `unknown`, for routing in a flow.

RDAP JSON parsing is implemented directly against the RFC 9083 schema
rather than a third-party library: RDAP is already fully specified,
self-describing JSON, so there is no parsing algorithm to wrap the way
legacy WHOIS free text needs one.

## Error contract

Every node returns a structured error (`{ error: { code, message } }`)
instead of ever panicking or crashing: malformed WHOIS text, JSON that
isn't valid or isn't a recognizable RDAP object of the kind the node
expects, or a required field left empty all come back as a clean
domain-level error rather than a raw exception. Payload-size and
resource limits are the deployed Axiom platform's concern, not this
package's.

## License

MIT. See [LICENSE](LICENSE).
