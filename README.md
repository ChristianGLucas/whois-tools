# whois-tools

Composable Axiom nodes for deterministic parsing of domain and IP
registration records: legacy WHOIS text and RDAP JSON (RFC 9083, the IETF
successor protocol) into a single normalized shape.

Built for the [Axiom](https://axiomide.com) marketplace, handle
`christiangeorgelucas`.

## Use it from your agent or app

Every node in this package is a **live, auto-scaling API endpoint** on the
[Axiom](https://axiomide.com) marketplace — call it from an AI agent or your own
code, with nothing to self-host.

**📦 See it on the marketplace:**
https://dev.axiomide.com/marketplace/christiangeorgelucas/whois-tools@0.1.2

**Hook it up to an AI agent (MCP).** Add Axiom's hosted MCP server to any MCP
client and every node becomes a typed tool your agent can call — search the
catalog, inspect a schema, and invoke it directly.

```bash
# Claude Code
claude mcp add --transport http axiom https://api.axiomide.com/mcp \
  --header "Authorization: Bearer $AXIOM_API_KEY"
```

Claude Desktop, Cursor, or any config-based client:

```json
{
  "mcpServers": {
    "axiom": {
      "type": "http",
      "url": "https://api.axiomide.com/mcp",
      "headers": { "Authorization": "Bearer YOUR_AXIOM_API_KEY" }
    }
  }
}
```

**Call it from the CLI.**

```bash
axiom invoke christiangeorgelucas/whois-tools/ParseWhois --input '{ ... }'
```

**Call it over HTTP.**

```bash
curl -X POST https://api.axiomide.com/invocations/v1/nodes/christiangeorgelucas/whois-tools/0.1.2/ParseWhois \
  -H "Authorization: Bearer $AXIOM_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{ ... }'
```

> Input/output schema for each node is on the marketplace page above, or via
> `axiom inspect node christiangeorgelucas/whois-tools/ParseWhois`.

### Get started free

Install the CLI:

```bash
# macOS / Linux — Homebrew
brew install axiomide/tap/axiom

# macOS / Linux — install script
curl -fsSL https://raw.githubusercontent.com/AxiomIDE/axiom-releases/main/install.sh | sh
```

**Windows:** download the `windows/amd64` `.zip` from the
[releases page](https://github.com/AxiomIDE/axiom-releases/releases), unzip it,
and put `axiom.exe` on your `PATH`.

Then `axiom version` to verify, `axiom login` (GitHub or Google) to authenticate,
and create an API key under **Console → API Keys**. Docs and sign-up at
**[axiomide.com](https://axiomide.com)**.

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
