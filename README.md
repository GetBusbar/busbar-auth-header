<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-header

First-party signed kind:auth plugin cdylib: the header auth, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `header` | `busbar-auth-header-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-auth-header/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-header/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-auth-header` is a `kind: auth` busbar plugin: one mechanism, a credential presented
in an HTTP header (or, for `query-key`, as a query parameter), serving both the operator's own
bound credential and the caller's verified credential (passthrough).

## Styles

| style | presents |
|---|---|
| `bearer` | `authorization: Bearer <credential>` |
| `api-key` | `<credential>` in a header, `api-key` unless `header` names another |
| `x-goog-api-key` | `<credential>` in a header, `x-goog-api-key` unless `header` names another |
| `query-key` | `<credential>` as the query parameter `key` unless `param` names another (never a header) |

Nonblank credential bytes are preserved, including leading and trailing space and tab, unless
the selected raw presentation explicitly sets `trim_start`. A credential containing only space
and tab presents no auth field in either credential mode. The same byte and blank-credential
policy applies to `query-key`; the host percent-encodes its presented query value. An own credential must be UTF-8; otherwise
`open_outbound` fails with a credential refusal. A non-UTF-8 caller credential presents no field
and raises the selected style's diagnostic. Legal non-ASCII UTF-8 bytes are retained without
normalization. A credential holding a byte no header value may carry also presents nothing; the
request goes without an auth header, a WARN diagnostic is raised on each such request, and an
unpresentable own credential is logged once at open and reported not ready.
The bearer style applies this field-value policy and adds `Bearer `; it does not restrict the
credential to OAuth's bearer-token grammar. The upstream service judges the credential's own syntax.

## Config

Configured under the `header` module name. The style's settings are a JSON object; any key the
style does not read is refused by name (``settings: unknown key `<key>` ``), except the provider keys
the kernel writes into every style (`token_url`, `token_uri`, `scope`, `subject`), which are ignored.
Instance validation, open and refresh check object shape and known key names across all styles
(`settings.<key>: unknown key`); values and the selected style's keys are judged when binding it.

| key | styles | meaning |
|---|---|---|
| `header` | `api-key`, `x-goog-api-key` | the credential header name (an RFC 9110 token, any case, presented lower-case; message framing, routing and connection-control fields are refused) |
| `param` | `query-key` | the query parameter name |
| `families` | `bearer`, `api-key`, `x-goog-api-key` | `[{prefix, header?, trim_start?}]`: the first row whose `prefix` the credential starts with sets the presentation (no `header` = a bearer) |
| `own` | the header styles | `{header?, trim_start?}`: how an own credential matching no family is presented (no `header` = a bearer) |
| `passthrough` | the header styles | `{header?, trim_start?}`: the same for the caller's credential |
| `protocol` | the header styles | the lane's protocol name, which an unpresentable-credential diagnostic names |
| `trim_start` | in `families`, `own`, `passthrough` | for a raw header, remove leading Unicode whitespace; other presentation bytes are preserved |

Family prefix selection ignores leading Unicode whitespace, preserving the existing family rule.
Without `trim_start`, the emitted value retains both ASCII and non-ASCII whitespace. If the
selected raw trim removes the whole credential, it presents no field and
does not report invalid bytes. Query parameter names retain their case; header names do not.

Refusals, each by setting name: `header`, `param` or `protocol` present but blank
(`must not be blank`); a `header` (or `families[i].header`, `own.header`, `passthrough.header`)
that is not an RFC 9110 token or names framing, routing or connection controls; `families[i].prefix` empty, blank or starting with whitespace; `trim_start` set in a
`families[i]`, `own` or `passthrough` that names no `header` (a bearer is never trimmed); `param` that is not a token
free of `&` and `#`; `protocol` holding a control character. An absent (or null) setting keeps its
default.

The plugin declares `BUSBAR-4030` for invalid credentials under a scheme with a family table.
The other emitted IDs, `BUSBAR-4013` and `BUSBAR-7087`, belong to the core catalogue and are not
redeclared here. A per-request diagnostic records names and reasons, never credential bytes.

## Build

```bash
cargo build --release -p busbar-auth-header-plugin
```

## Tests

```bash
BUSBAR_CHECKOUT=<busbar checkout at .busbar-ref> cargo test --workspace --locked
```

The catalogue tests read the core diagnostic catalogue from `BUSBAR_CHECKOUT` (CI's plugin-ci
exports it) and fail when it is unset.

## License

Apache-2.0. See [LICENSE](LICENSE).
