# Email Domain Check

A free check for your domain's email authentication: **SPF, DKIM, DMARC, MX, blocklists, MTA-STS and TLS-RPT**. You get an A to F grade, a plain-English explanation of every problem, and the exact DNS records to fix it for your provider.

**Use it:** [derops.dev/email-check](https://derops.dev/email-check). Results can be shared as a link: `derops.dev/email-check?d=yourdomain.com`.

It runs entirely in your browser. DNS lookups go straight from your browser to public DNS-over-HTTPS resolvers (Google, with Cloudflare as fallback). There's no backend, nothing is logged, and nothing is stored.

## Why it matters

Since 2024, Gmail and Yahoo require SPF or DKIM from every sender and DMARC from bulk senders, and Outlook has followed. Mail from domains that get this wrong goes to spam or is rejected. The common failures are rarely obvious:

- **Two SPF records** after adding a new tool. SPF then fails for *every* message.
- **More than 10 DNS lookups** in SPF from piling up `include:` entries. Receivers stop counting and SPF silently fails.
- **DKIM set up for the newsletter tool but not for Google Workspace or Microsoft 365 itself**, so everyday mail goes out unsigned.
- **DMARC stuck at `p=none`** forever, or with no report address.

## What it checks

| Area | Checks |
|---|---|
| MX | Records, provider detection (Google Workspace, Microsoft 365, Zoho, Proton, Cloudflare Email Routing, self-hosted), null MX |
| SPF | One record only, `+all` / `?all` / missing `all`, recursive **10-lookup limit**, void lookups, broken includes, provider include present, authorized senders |
| DKIM | Probes the provider's selectors and ~25 common ones (or your own), flags missing provider keys, 1024-bit and revoked keys, ignores wildcard DNS |
| DMARC | Present and valid, policy, `rua` reporting, `pct`, subdomain inheritance from the parent domain |
| Blocklists | Sending IPs (from SPF and self-hosted MX) on Spamhaus ZEN, SpamCop, Barracuda and PSBL; the domain on Spamhaus DBL. Lists that refuse public resolvers are reported as not checked, never guessed |
| Transport | MTA-STS and TLS-RPT |
| Parked domains | Domains that don't send mail are checked for `v=spf1 -all`, DMARC `p=reject` and null MX |

**Grade:** F with any critical finding, D with two or more high, C with one high, B with only medium, A otherwise.

**Fixes:** SPF is *merged* with what you already have, so existing senders keep working. DKIM steps are specific to Google Workspace, Microsoft 365, Zoho, Proton and Mailcow. DMARC starts in monitoring mode and is tightened once reports are clean.

## What it doesn't check

DNS is what receivers verify first, but it isn't everything: this can't see your sending reputation, content, list quality or whether your provider actually signs with the DKIM key it publishes. Blocklist coverage is partial by design (public resolvers only).

## Development

The logic lives in [`src/emailcheck.js`](src/emailcheck.js) and runs unchanged in the browser and in Node. Tests use a fake resolver with recorded DNS answers:

```bash
node --test test/*.test.js
python3 web/build.py        # builds web/dist/email-check.html (single self-contained file)
```

`web/site.json` holds the Upwork links and offers shown on the page.

## Need it fixed?

I'm Ahmed Darder ([DerOps](https://derops.dev)). I set up email authentication and deliverability for businesses on Google Workspace, Microsoft 365 and self-hosted Mailcow. Work is booked through Upwork; details on the [check page](https://derops.dev/email-check#fix).

## License

MIT
