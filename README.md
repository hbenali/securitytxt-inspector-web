# security.txt Validator

A free, single-page validator and generator for `security.txt` files ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)). Live at [securitytxt.hbenali.ovh](https://securitytxt.hbenali.ovh).

No backend, no build step, no dependencies, and no network call at all (`connect-src 'none'`): static HTML, CSS and one small script.

## Features

- **Paste mode**: validates the pasted file line by line
  - `Contact` required, each value a `mailto:`, `https:` or `tel:` URI
  - `Expires` required, exactly once, ISO 8601 / RFC 3339 date-time, must be in the future, warning when more than a year ahead or within 30 days
  - `Encryption`, `Acknowledgments`, `Canonical`, `Policy`, `Hiring`, `CSAF` URI checks (https only for web URIs, `Encryption` never an email), `Preferred-Languages` at most once with valid language tags
  - `Field: value` line format, comments, unknown and misspelled fields, BOM, invalid UTF-8 characters
  - detects the OpenPGP clearsign wrapper; **the signature is not verified** (a browser page has no key to check it with)
- **Generator** that writes a correct file, with `Expires` defaulting to one year ahead (less a day, since RFC 9116 asks for under a year); copy or download it
- **curl helper**: `?domain=example.com` builds the command to fetch the domain's file
- Links to the sibling tools of the suite for the same domain
- Dark editorial design with a light mode, self-hosted fonts, PWA, strict CSP (`script-src 'self'`)

## Why there is no fetch mode

Tested in headless Chrome against hbenali.ovh, github.com, google.com and cloudflare.com: none of them sends CORS headers for `/.well-known/security.txt` (hbenali.ovh redirects to a host that answers 404), so the browser blocks every request. Even for a site that did, the strict CSP cannot list an arbitrary domain in `connect-src`. So the page never fetches, and gives the `curl` command instead.

## Running locally

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

## Deployment

GitHub Pages, deployed on every push to `main` (see `.github/workflows/`).

## License

MIT, see [LICENSE](LICENSE).
