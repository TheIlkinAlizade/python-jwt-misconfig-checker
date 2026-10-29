# python-jwt-misconfig-checker

[![CI](https://github.com/TheIlkinAlizade/python-jwt-misconfig-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/TheIlkinAlizade/python-jwt-misconfig-checker/actions/workflows/ci.yml)

Offline CLI that analyzes JSON Web Tokens (JWTs) for security misconfigurations, with severity ratings, explanations, and fix advice. Defensive and educational.

> **Do not publish real tokens.** A real token can be replayed until it expires and often contains personal data. Use only tokens you generate for testing, such as those built by the helpers in `tests/tokens.py`. Reports from this tool can contain masked claim values, so treat them as sensitive too.

> **Responsible use:** use this tool only on tokens and systems you own or are authorized to test.

## What it does and who it's for

`jwt-misconfig-check` decodes a JWT and checks its header and payload against known weaknesses. Each finding has a severity, an explanation, fix advice, and references to RFC 8725 and OWASP guidance.

It is for students learning how JWT attacks and defenses work, developers who want a quick review of the tokens their application issues, and CI pipelines that should fail when a sample token shows a serious weakness. It is not a vulnerability scanner and it does not test servers.

Everything runs locally. The tool only reads the token you give it. It makes no network requests and sends nothing anywhere.

## Install

Requires Python 3.11 or newer. The project is not published on PyPI, so install from source:

```bash
git clone https://github.com/TheIlkinAlizade/python-jwt-misconfig-checker.git
cd python-jwt-misconfig-checker
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`. For development (tests, ruff, mypy) use `pip install -e ".[dev]"`.

## Usage

Prefer stdin or a file over a command-line argument, because arguments are stored in your shell history.

```bash
jwt-misconfig-check -                    # read the token from stdin
jwt-misconfig-check --file token.txt     # read the token from a file
jwt-misconfig-check <token>              # pass the token directly
```

| Option | Meaning |
|---|---|
| `--format human\|json` | Report format (default `human`) |
| `--fail-on LEVEL` | `info`, `low`, `medium`, `high` or `critical`; default `high` |
| `--show-token` | Print the full token in the report (redacted by default) |
| `--wordlist PATH` | Optional offline weak HMAC secret check |
| `--i-own-this-token` | Required with `--wordlist`; confirms you own the token |
| `--version` | Print the version |

Exactly one input source is required: the token argument, `-`, or `--file`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no findings at or above `--fail-on` |
| 1 | at least one finding at or above `--fail-on` |
| 2 | usage or input error (malformed token, missing file, `--wordlist` without `--i-own-this-token`) |

## Sample output

Output for a test token with `alg: none` and a minimal payload (long lines shortened with `...`):

```text
Token: eyJhbGci*** (81 characters)

CRITICAL JWT-ALG-001 The token declares alg none
  Where:    header.alg
  Evidence: 'none'
  Why:      The header declares the 'none' algorithm, which means the token carries no signature. ...
  Fix:      Configure the verifier with a fixed allowlist of algorithms and never derive the algorithm from the token. ...
  See:      RFC 7519 section 6 (Unsecured JWTs); RFC 8725 section 3.2 (Do not trust the alg header); ...

HIGH JWT-CLM-001 The token has no expiry
  Where:    payload.exp
  Evidence: <absent>
  ...

MEDIUM JWT-CLM-002 The token has no iss claim
  ...

MEDIUM JWT-CLM-002 The token has no aud claim
  ...

4 finding(s): 1 CRITICAL, 1 HIGH, 2 MEDIUM
```

Use `--format json` for machine-readable output in CI.

## Checks

| ID | Severity | What it detects | Why it matters | How to fix |
|---|---|---|---|---|
| JWT-ALG-001 | critical | `alg: none` in any capitalization; missing or non-string `alg` | The token carries no signature, so anyone can forge it | Verify against a fixed algorithm allowlist; never take the algorithm from the token |
| JWT-ALG-002 | high to low | Weak digests, encryption algorithms in a signed token, odd capitalization, unregistered values | Lenient verifiers normalize or fall back in exploitable ways | Allow only exact, strong algorithms such as RS256, ES256, EdDSA |
| JWT-ALG-003 | medium to info | Asymmetric tokens whose header suggests algorithm-confusion exposure | A public key can be abused as an HMAC secret if the verifier trusts the header | Pin the algorithm to the key type |
| JWT-HDR-001 | info, low | Unexpected or non-string `typ` | Tokens minted for one purpose can be replayed in another | Use explicit typing such as `at+jwt` and enforce it |
| JWT-HDR-002 | high, medium, low | `jwk`, `x5c`, `jku`, `x5u`; risky URLs (http, private hosts, credentials) | The token supplies its own key or triggers server-side requests (SSRF) | Ignore these headers; resolve keys from your own configuration |
| JWT-HDR-003 | high, medium, low | `kid` shaped like path traversal, SQL, or shell injection | A `kid` used in a path or query can load an attacker-chosen key | Treat `kid` as an opaque identifier; use map lookups or parameterized queries |
| JWT-CLM-001 | high to medium | Missing `exp`, expired token, lifetime over 24 hours or 30 days, future `iat`/`nbf`, invalid dates | Tokens that never expire stay useful after theft | Short lifetimes; validate every time claim |
| JWT-CLM-002 | medium, low | Missing or malformed `iss` and `aud` | Tokens can be substituted across services or issuers | Require the expected issuer and your own audience |
| JWT-DAT-001 | high to low | Password or secret-like field names, API key formats, private keys, emails, card numbers | The payload is only encoded, so anyone holding the token can read it | Keep claims minimal; use JWE if confidentiality is required |
| JWT-SEC-001 | critical | HMAC secret found in your wordlist (opt-in) | A guessable secret lets anyone forge tokens | Use 256 random bits from a secrets manager, or asymmetric keys |

## How detection works

- **Parsing.** The token is split into three segments, decoded as strict canonical base64url, and each of header and payload must be a UTF-8 JSON object. The parser rejects duplicate keys, `NaN` constants, tokens over 32 KB, and JSON nested deeper than 32 levels. Malformed input is an input error (exit 2), never a crash.
- **Header checks.** Compare `alg` against the JOSE algorithm registry, and inspect `typ`, `jwk`, `x5c`, `jku`, `x5u`. URLs are judged by their text only, using `urllib.parse` and `ipaddress`. Nothing is resolved or fetched.
- **`kid` check.** Matches path traversal, device files, SQL and shell patterns against the raw and percent-decoded value.
- **Claims checks.** Compare `exp`, `nbf` and `iat` against an injected clock with a 60-second skew allowance, and require `iss` and `aud`.
- **Sensitive data.** Walks the payload to a bounded depth, matching field names word by word and values against known formats. Card numbers must pass the Luhn check.
- **Weak secret (opt-in).** Recomputes the HMAC of the signing input for each wordlist entry and compares in constant time. It only verifies; it never creates tokens.
- **Algorithm confusion.** Explains the RS256-to-HS256 attack and flags header patterns that raise exposure. It contains no forging code.

## Security design

- No network access of any kind.
- The wordlist check is not part of the default run. It needs `--wordlist` and `--i-own-this-token`.
- Tokens are redacted in reports unless `--show-token` is set.
- Found secrets and sensitive values are never printed. Evidence shows only a masked form or a length.
- Everything taken from a token is escaped before printing, so a crafted token cannot inject terminal control sequences or Rich markup.
- Input reads and wordlist reads are size-capped, and parser behavior is covered by fuzz tests.

## False positives

Findings are indicators to investigate, not proof of a vulnerability.

- **`kid`:** an apostrophe, semicolon or a path-like value can be a legitimate naming convention in some systems.
- **`jku` / `x5u`:** a URL on an internal or `http` host can be intentional in a private deployment.
- **Sensitive data:** a field named `phone` or `passport` may hold a harmless value, and a long digit string that passes the Luhn check may not be a card.
- **Algorithm confusion:** an asymmetric token is reported as a risk note even when the server pins its algorithm correctly.
- **Time claims:** a token legitimately issued with a long lifetime (for example a refresh token) is reported as long-lived.

## Limitations

- The tool sees only the token. It cannot tell whether your server verifies it correctly.
- The signature is never verified, because the tool has no key. A clean report does not mean a token or server is secure.
- The weak-secret check proves a secret is weak when found. Not finding it proves nothing.
- Pattern rules produce false negatives: secrets under innocuous names, unusual key formats, injection payloads that avoid the known shapes.
- A hostname that looks public but resolves to a private address (DNS rebinding) cannot be detected offline.
- Unicode lookalike values (for example a Greek letter in `none`) are not treated as `none`.
- Encrypted tokens (JWE, five segments) are not analyzed.
- Only the algorithms and headers listed above are known to the tool. Custom or future parameters are not assessed.
- No attacks are executed and no tokens are forged.

## Threat model

**What is protected:** the analyst's terminal and machine, and the honesty of the report.

**Attacker model:** whoever created the token controls every byte of it. They may try to crash or slow the tool, inject terminal escape sequences or markup into the report, or craft values that evade the patterns. The command line, wordlist and files you pass are treated as trusted operator input.

**What the tool does about it:** strict parsing, size and depth limits, escaped output, redacted tokens and secrets, and tests for malformed and adversarial input.

**What it can tell you:** whether a token's header and claims contain patterns widely associated with JWT misconfigurations, and what the standards recommend instead.

**What it cannot tell you:** how your server validates tokens, whether keys are strong or rotated, whether tokens can be revoked, or whether your application is exploitable.

**Out of scope:** testing live systems, forging tokens, exploiting servers, and real-time protection. The tool does not prevent anything. It reports.

## Server-side fixes

- Fix the verification algorithm per key. Spring Security: `NimbusJwtDecoder.withPublicKey(key).signatureAlgorithm(SignatureAlgorithm.RS256)`. PyJWT: `algorithms=["RS256"]`.
- Ignore `jku`, `x5u`, `jwk` and `x5c`; use a configured JWKS endpoint.
- Treat `kid` as an opaque map key, never as part of a path or query.
- Validate `exp`, `nbf`, `iss` and `aud` on every request. In Spring Security, `iss` and `aud` need explicit validators.
- Keep claims minimal and use strong, random HMAC secrets.

## Development

```bash
pip install -e ".[dev]"
ruff format --check .
ruff check .
mypy src tests
pytest
```

CI runs the same checks on Python 3.11, 3.12 and 3.13, then builds the package and runs the installed command. See `CONTRIBUTING.md` for how to add a check.

## References

- RFC 7519: JSON Web Token (JWT)
- RFC 7515 and RFC 7518: JSON Web Signature and JSON Web Algorithms
- RFC 8725: JSON Web Token Best Current Practices
- OWASP JWT Cheat Sheet and OWASP Top 10

## Project status

This is a hobby and portfolio project, released as is. It will not receive regular updates, and bugs or security issues may stay unfixed. Pull requests and forks are welcome. Read the Limitations section before relying on any result. See `SECURITY.md` for responsible use and how to report issues.

## Disclaimer

Use this tool only on tokens and systems you own or are authorized to test. It is provided as is, without warranty, for defensive and educational purposes. It is not a substitute for code review, penetration testing or a security audit. Findings are indicators, not proof, and absence of findings is not proof of safety. There is no guarantee of maintenance, support or fixes.

## License

MIT. See `LICENSE`.