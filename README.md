<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-header

First-party signed kind:auth plugin cdylib: the header auth, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `header` | `busbar-auth-header-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-auth-header/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-header/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-auth-header` is a `kind: auth` busbar plugin: one mechanism, a credential presented verbatim
in an HTTP header (or, for `query-key`, as a query parameter), serving both the operator's own
bound credential and the caller's verified credential (passthrough).

## Styles

| style | presents |
|---|---|
| `bearer` | `authorization: Bearer <credential>` |
| `api-key` | `<credential>` in a header, `api-key` unless `header` names another |
| `x-goog-api-key` | `<credential>` in a header, `x-goog-api-key` unless `header` names another |
| `query-key` | `<credential>` as the query parameter `key` unless `param` names another (never a header) |

A credential is presented with its leading and trailing space and tab removed (a field value never
carries them, RFC 9110 section 5.5). A credential that is empty after that presents nothing: no
auth field. A credential holding a byte no header value may carry also presents nothing; the
request goes without an auth header, a WARN diagnostic is raised on each such request, and an
unpresentable own credential is logged once at open and reported not ready.

## Config

Configured under the `header` module name. The style's settings are a JSON object; any key the
style does not read is refused by name (`settings: unknown key <key>`), except the provider keys
the kernel writes into every style (`token_url`, `token_uri`, `scope`, `subject`), which are ignored.

| key | styles | meaning |
|---|---|---|
| `header` | `api-key`, `x-goog-api-key` | the header name (an RFC 9110 token, any case, presented lower-case) |
| `param` | `query-key` | the query parameter name |
| `families` | `bearer`, `api-key`, `x-goog-api-key` | `[{prefix, header?, trim_start?}]`: the first row whose `prefix` the credential starts with sets the presentation (no `header` = a bearer) |
| `own` | the header styles | `{header?, trim_start?}`: how an own credential matching no family is presented |
| `passthrough` | the header styles | `{header?, trim_start?}`: the same for the caller's credential |
| `protocol` | the header styles | the lane's protocol name, which an unpresentable-credential diagnostic names |
| `trim_start` | in `families`, `own`, `passthrough` | also trim leading whitespace (now subsumed by the trimming above) |

Refusals, each by setting name: `header`, `param` or `protocol` present but blank
(`must not be blank`); a `header` (or `families[i].header`, `own.header`, `passthrough.header`)
that is not an RFC 9110 token; `families[i].prefix` empty or blank; `param` that is not a token
free of `&` and `#`; `protocol` holding a control character. An absent (or null) setting keeps its
default.

## Build

```bash
cargo build --release -p busbar-auth-header-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
