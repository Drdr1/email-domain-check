/*
 * DerOps Email Domain Check: core logic.
 * Runs in the browser (DNS-over-HTTPS) or in Node (tests inject a fake resolver).
 * Nothing here talks to anything except public DNS resolvers.
 */
const EmailCheck = (() => {
  const VERSION = "1.0";
  const TYPES = { A: 1, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };

  /* ------------------------------------------------------------------ DNS */

  function parseTxtData(data) {
    if (typeof data !== "string") return "";
    const s = data.trim();
    if (!s.startsWith('"')) return s;
    const chunks = s.match(/"((?:[^"\\]|\\.)*)"/g) || [];
    return chunks.map((c) => c.slice(1, -1).replace(/\\(.)/g, "$1")).join("");
  }

  function dohResolver(fetchImpl) {
    const f = fetchImpl || ((...a) => fetch(...a));
    const endpoints = [
      (n, t) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}`,
      (n, t) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}`,
    ];
    const cache = new Map();
    return function resolve(name, type) {
      const key = name.toLowerCase() + "|" + type;
      if (!cache.has(key)) {
        cache.set(key, (async () => {
          let lastErr = "no resolver answered";
          for (const ep of endpoints) {
            try {
              const r = await f(ep(name, type), { headers: { accept: "application/dns-json" } });
              if (!r.ok) throw new Error("HTTP " + r.status);
              const j = await r.json();
              if (j.Status === 3) return { status: "nxdomain", records: [] };
              if (j.Status !== 0) throw new Error("DNS status " + j.Status);
              const recs = (j.Answer || [])
                .filter((a) => a.type === TYPES[type])
                .map((a) => (type === "TXT" ? parseTxtData(a.data) : String(a.data).trim()));
              return { status: "ok", records: recs };
            } catch (e) { lastErr = String(e.message || e); }
          }
          return { status: "error", records: [], error: lastErr };
        })());
      }
      return cache.get(key);
    };
  }

  const stripDot = (h) => h.toLowerCase().replace(/\.$/, "");

  /* ------------------------------------------------------------- catalogs */

  const PROVIDERS = {
    google:    { name: "Google Workspace", mx: [/(^|\.)google\.com$/, /(^|\.)googlemail\.com$/], spf: "include:_spf.google.com", selectors: ["google"] },
    microsoft: { name: "Microsoft 365", mx: [/\.mail\.protection\.outlook\.com$/, /\.mx\.microsoft$/], spf: "include:spf.protection.outlook.com", selectors: ["selector1", "selector2"] },
    zoho:      { name: "Zoho Mail", mx: [/(^|\.)zoho\.(com|eu|in|com\.au|jp)$/, /(^|\.)zohomail\.com$/], spf: "include:zoho.com", selectors: ["zoho", "zmail"] },
    proton:    { name: "Proton Mail", mx: [/(^|\.)protonmail\.ch$/, /(^|\.)proton\.ch$/], spf: "include:_spf.protonmail.ch", selectors: ["protonmail", "protonmail2", "protonmail3"] },
    cloudflare:{ name: "Cloudflare Email Routing", mx: [/\.mx\.cloudflare\.net$/], spf: "include:_spf.mx.cloudflare.net", selectors: [], receiveOnly: true },
    mailcow:   { name: "Mailcow / self-hosted", mx: [], spf: "mx", selectors: ["dkim"] },
  };

  const SENDERS = [
    [/^_spf\.google\.com$/, "Google Workspace"],
    [/^spf\.protection\.outlook\.com$/, "Microsoft 365"],
    [/(^|\.)sendgrid\.net$/, "SendGrid"],
    [/^servers\.mcsv\.net$/, "Mailchimp"],
    [/^spf\.mandrillapp\.com$/, "Mandrill"],
    [/(^|\.)amazonses\.com$/, "Amazon SES"],
    [/(^|\.)mailgun\.org$/, "Mailgun"],
    [/^spf\.(brevo|sendinblue)\.com$/, "Brevo"],
    [/(^|\.)zoho\.(com|eu|in)$/, "Zoho"],
    [/(^|\.)protonmail\.ch$/, "Proton Mail"],
    [/(^|\.)mtasv\.net$/, "Postmark"],
    [/(^|\.)mlsend\.com$/, "MailerLite"],
    [/(^|\.)salesforce\.com$/, "Salesforce"],
    [/(^|\.)zendesk\.com$/, "Zendesk"],
    [/(^|\.)hubspotemail\.net$/, "HubSpot"],
    [/(^|\.)constantcontact\.com$/, "Constant Contact"],
    [/(^|\.)mailjet\.com$/, "Mailjet"],
    [/(^|\.)sparkpostmail\.com$/, "SparkPost"],
    [/(^|\.)mx\.cloudflare\.net$/, "Cloudflare Email Routing"],
    [/(^|\.)helpscoutemail\.com$/, "Help Scout"],
    [/(^|\.)freshdesk\.com$/, "Freshdesk"],
  ];

  const COMMON_SELECTORS = [
    "google", "selector1", "selector2", "dkim", "default", "mail", "smtp",
    "k1", "k2", "s1", "s2", "mandrill", "mxvault", "zoho", "zmail",
    "protonmail", "protonmail2", "protonmail3", "mailjet", "mlsend", "mlsend2",
    "resend", "pm", "sig1", "everlytickey1", "cm",
  ];

  const IP_BLOCKLISTS = [
    { zone: "zen.spamhaus.org", name: "Spamhaus ZEN", severe: true },
    { zone: "bl.spamcop.net", name: "SpamCop" },
    { zone: "b.barracudacentral.org", name: "Barracuda" },
    { zone: "psbl.surriel.com", name: "PSBL" },
  ];
  const DOMAIN_BLOCKLISTS = [{ zone: "dbl.spamhaus.org", name: "Spamhaus DBL", severe: true }];

  const TWO_PART_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.za",
    "com.br", "com.eg", "com.sa", "com.tr", "co.jp", "co.in", "com.mx", "com.ar", "co.il", "com.sg", "com.my",
  ]);
  function orgDomain(d) {
    const parts = d.split(".");
    if (parts.length <= 2) return d;
    const last2 = parts.slice(-2).join(".");
    return TWO_PART_SUFFIXES.has(last2) ? parts.slice(-3).join(".") : last2;
  }

  /* ----------------------------------------------------------------- SPF */

  function parseSpf(record) {
    const terms = record.trim().split(/\s+/).slice(1);
    return terms.map((raw) => {
      let q = "+", t = raw;
      if ("+-~?".includes(t[0])) { q = t[0]; t = t.slice(1); }
      const m = t.match(/^([a-z0-9]+)(?:[:=](.*))?$/i) || [null, t, undefined];
      const isMod = /^[a-z0-9]+=/.test(t);
      return { raw, qualifier: q, name: (m[1] || "").toLowerCase(), value: m[2], modifier: isMod };
    });
  }

  async function evalSpf(domain, resolve, state) {
    // Walks include/redirect recursively, counting DNS lookups the way receivers do.
    state = state || { lookups: 0, voids: 0, queries: 0, includes: [], ip4: [], errors: [], seen: new Set() };
    if (state.seen.has(domain) || state.queries > 60) return state;
    state.seen.add(domain);
    state.queries++;
    const r = await resolve(domain, "TXT");
    const spfs = r.records.filter((t) => /^v=spf1(\s|$)/i.test(t));
    if (r.status === "error") { state.errors.push(`couldn't look up ${domain}`); return state; }
    if (!spfs.length) { state.errors.push(`${domain} has no SPF record`); state.voids++; return state; }
    if (spfs.length > 1) state.errors.push(`${domain} has ${spfs.length} SPF records`);
    for (const term of parseSpf(spfs[0])) {
      const n = term.name;
      if (["include", "a", "mx", "ptr", "exists"].includes(n) || (term.modifier && n === "redirect")) state.lookups++;
      if (n === "include" && term.value) {
        const target = stripDot(term.value);
        state.includes.push(target);
        await evalSpf(target, resolve, state);
      } else if (term.modifier && n === "redirect" && term.value) {
        await evalSpf(stripDot(term.value), resolve, state);
      } else if (n === "ip4" && term.value) {
        state.ip4.push(term.value);
      }
    }
    return state;
  }

  function topAll(terms) {
    const all = terms.filter((t) => t.name === "all" && !t.modifier);
    return all.length ? all[all.length - 1].qualifier : null;
  }

  function sendersFrom(includes) {
    const found = new Set();
    for (const inc of includes) for (const [re, name] of SENDERS) if (re.test(inc)) found.add(name);
    return [...found];
  }

  /* --------------------------------------------------------------- DMARC */

  function parseTags(record) {
    const tags = {};
    for (const part of record.split(";")) {
      const i = part.indexOf("=");
      if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
    }
    return tags;
  }

  /* ---------------------------------------------------------------- DKIM */

  function dkimKeyBits(record) {
    const tags = parseTags(record);
    const p = (tags.p || "").replace(/\s+/g, "");
    if (!p) return { revoked: true, bits: 0 };
    const bytes = Math.floor((p.length * 3) / 4);
    if ((tags.k || "rsa").toLowerCase() === "ed25519") return { bits: 256, ed25519: true };
    return { bits: bytes < 180 ? 1024 : bytes < 330 ? 2048 : 4096 };
  }

  /* ----------------------------------------------------------- blocklists */

  function reverseIp(ip) { return ip.split(".").reverse().join("."); }
  function isSingleIpv4(v) {
    const m = String(v).match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d+))?$/);
    return m && (!m[2] || m[2] === "32") ? m[1] : null;
  }
  async function checkList(name, list, resolve) {
    const r = await resolve(`${name}.${list.zone}`, "A");
    if (r.status === "nxdomain") return "clean";
    if (r.status !== "ok") return "unknown";
    if (!r.records.length) return "clean";
    // Error/refusal codes (e.g. Spamhaus answers public resolvers with 127.255.255.x)
    if (r.records.every((a) => /^127\.255\.255\./.test(a) || a === "127.0.1.255")) return "unknown";
    return r.records.some((a) => /^127\./.test(a)) ? "listed" : "unknown";
  }

  /* ------------------------------------------------------------ the check */

  function normalizeDomain(input) {
    let d = String(input || "").trim().toLowerCase();
    d = d.replace(/^[a-z]+:\/\//, "").replace(/^[^@]*@/, "").replace(/[\/?#:].*$/, "").replace(/\.$/, "");
    if (d.startsWith("www.")) d = d.slice(4);
    if (!/^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/.test(d)) return null;
    return d;
  }

  async function check(domainInput, opts) {
    opts = opts || {};
    const resolve = opts.resolve || dohResolver();
    const domain = normalizeDomain(domainInput);
    if (!domain) throw new Error("Enter a domain like example.com.");
    const findings = [];
    const add = (f) => findings.push(f);
    const facts = { domain };

    /* MX */
    const mxRes = await resolve(domain, "MX");
    if (mxRes.status === "error") throw new Error("DNS lookups aren't getting through. Check your connection and try again.");
    const mx = mxRes.records.map((s) => {
      const [pref, host] = s.split(/\s+/);
      return { pref: Number(pref), host: stripDot(host || "") };
    }).sort((a, b) => a.pref - b.pref);
    const nullMx = mx.length === 1 && (mx[0].host === "" || mx[0].host === ".");
    let provider = null;
    for (const [key, p] of Object.entries(PROVIDERS)) {
      if (mx.some((m) => p.mx.some((re) => re.test(m.host)))) { provider = key; break; }
    }
    if (!provider && mx.length && !nullMx) provider = "mailcow";
    if (opts.provider && PROVIDERS[opts.provider]) provider = opts.provider;
    facts.mx = mx; facts.nullMx = nullMx; facts.provider = provider;

    /* SPF */
    const txt = await resolve(domain, "TXT");
    const spfRecords = txt.records.filter((t) => /^v=spf1(\s|$)/i.test(t));
    const spf = spfRecords.length ? await evalSpf(domain, resolve) : null;
    const spfTerms = spfRecords.length ? parseSpf(spfRecords[0]) : [];
    const allQ = topAll(spfTerms);
    const hasRedirect = spfTerms.some((t) => t.modifier && t.name === "redirect");
    const senders = spf ? sendersFrom(spf.includes) : [];
    facts.spf = { records: spfRecords, lookups: spf ? spf.lookups : 0, senders, all: allQ };

    /* DKIM */
    const selectors = [...new Set([
      ...(opts.selector ? [opts.selector.trim().toLowerCase()] : []),
      ...(provider ? PROVIDERS[provider].selectors : []),
      ...COMMON_SELECTORS,
    ])].filter((s) => /^[a-z0-9._-]+$/.test(s));
    const probe = async (sel) => {
      const r = await resolve(`${sel}._domainkey.${domain}`, "TXT");
      const rec = r.records.find((t) => /(^|;)\s*(v=DKIM1|p=)/i.test(t) || /\bk=rsa\b/i.test(t));
      return rec ? { selector: sel, record: rec, ...dkimKeyBits(rec) } : null;
    };
    const [wild, ...probed] = await Promise.all([probe("derops-nonexistent-" + Date.now().toString(36)), ...selectors.map(probe)]);
    const dkim = wild ? [] : probed.filter(Boolean);
    facts.dkim = { selectorsTried: selectors.length, found: dkim, wildcard: !!wild };

    /* DMARC */
    let dmarcHost = `_dmarc.${domain}`;
    let dmarcRes = await resolve(dmarcHost, "TXT");
    let dmarcRecs = dmarcRes.records.filter((t) => /^v=DMARC1\s*(;|$)/i.test(t));
    let inherited = false;
    if (!dmarcRecs.length && orgDomain(domain) !== domain) {
      const parent = await resolve(`_dmarc.${orgDomain(domain)}`, "TXT");
      const recs = parent.records.filter((t) => /^v=DMARC1\s*(;|$)/i.test(t));
      if (recs.length) { dmarcRecs = recs; inherited = true; dmarcHost = `_dmarc.${orgDomain(domain)}`; }
    }
    const dmarc = dmarcRecs.length ? parseTags(dmarcRecs[0]) : null;
    if (dmarc && inherited) dmarc.p = dmarc.sp || dmarc.p;
    facts.dmarc = { records: dmarcRecs, tags: dmarc, inherited, host: dmarcHost };

    /* Is this domain used for sending? */
    const spfSends = spfTerms.some((t) => !t.modifier && t.name !== "all") || hasRedirect;
    const sending = spfSends || dkim.length > 0 || (mx.length > 0 && !nullMx && !(provider && PROVIDERS[provider].receiveOnly));
    facts.sending = sending;

    /* ---- findings: MX ---- */
    if (nullMx) add({ area: "MX", severity: "pass", title: "Null MX: this domain says it accepts no mail", detail: "Correct for a domain that doesn't use email." });
    else if (!mx.length) add({ area: "MX", severity: "info", title: "No MX records", detail: sending ? "This domain sends but doesn't receive mail. That's normal for a sending-only subdomain (newsletters, notifications); otherwise replies to it will bounce." : "This domain doesn't receive mail. If that's intended, publishing a null MX makes it explicit." });
    else add({ area: "MX", severity: "pass", title: `Mail handled by ${provider ? PROVIDERS[provider].name : "a custom server"}`, detail: mx.map((m) => `${m.pref} ${m.host}`).join(", ") });

    /* ---- findings: SPF ---- */
    if (!spfRecords.length) {
      add({ area: "SPF", severity: "high", id: "spf_missing", title: "No SPF record", detail: sending ? "Receivers can't tell which servers may send for your domain, so your mail is more likely to land in spam, and anyone can spoof you more easily." : "Without SPF, anyone can send mail that claims to come from this domain." });
    } else {
      if (spfRecords.length > 1) add({ area: "SPF", severity: "critical", id: "spf_multiple", title: `${spfRecords.length} SPF records`, detail: "Only one is allowed. With two, receivers treat SPF as broken (permerror) and it fails for every message." });
      if (allQ === "+") add({ area: "SPF", severity: "critical", id: "spf_plus_all", title: "SPF ends in +all", detail: "This authorizes every server on the internet to send as your domain, which is worse than having no SPF." });
      else if (allQ === "?") add({ area: "SPF", severity: "medium", id: "spf_neutral", title: "SPF ends in ?all (neutral)", detail: "Servers you didn't list get no penalty, so SPF gives almost no protection." });
      else if (!allQ && !hasRedirect) add({ area: "SPF", severity: "medium", id: "spf_no_all", title: "SPF has no ending all mechanism", detail: "Without ~all or -all, unlisted servers are treated as neutral." });
      if (spf.lookups > 10) add({ area: "SPF", severity: "critical", id: "spf_too_many_lookups", title: `SPF needs ${spf.lookups} DNS lookups (limit is 10)`, detail: "Receivers stop at 10 and treat SPF as broken (permerror), so it fails silently for everything. Common cause: too many include: entries from tools you've added over time." });
      else if (spf.lookups >= 8) add({ area: "SPF", severity: "medium", id: "spf_near_limit", title: `SPF uses ${spf.lookups} of 10 DNS lookups`, detail: "Close to the limit. Adding one more sending service could break SPF entirely." });
      if (spf.voids > 2) add({ area: "SPF", severity: "critical", id: "spf_void", title: "SPF points at names that don't exist", detail: `More than two lookups returned nothing (${spf.errors.join("; ")}), which receivers treat as an error.` });
      else {
        const nested = spf.errors.filter((e) => !e.startsWith(`${domain} has`));  // root duplicates are reported above
        if (nested.length) add({ area: "SPF", severity: "high", id: "spf_broken_include", title: "Part of your SPF record is broken", detail: nested.join("; ") + "." });
      }
      const need = provider && PROVIDERS[provider].spf;
      if (need && need.startsWith("include:") && !(provider && PROVIDERS[provider].receiveOnly)) {
        const inc = need.slice(8);
        if (!spf.includes.includes(inc)) add({ area: "SPF", severity: "high", id: "spf_provider_missing", title: `SPF doesn't include ${PROVIDERS[provider].name}`, detail: `Your mail is hosted on ${PROVIDERS[provider].name}, but your SPF doesn't authorize it (${need}). Mail you send from it can fail SPF.` });
      }
      if (!findings.some((f) => f.area === "SPF" && f.severity !== "pass")) add({ area: "SPF", severity: "pass", title: "SPF is valid", detail: `${spf.lookups} of 10 lookups used. Authorized senders: ${senders.length ? senders.join(", ") : "your own servers"}.` });
    }

    /* ---- findings: DKIM ---- */
    if (sending) {
      if (wild) add({ area: "DKIM", severity: "info", id: "dkim_wildcard", title: "DKIM couldn't be checked reliably", detail: "Your DNS answers every selector name (a wildcard record), so we can't tell which selectors are real. Enter your selector to check it." });
      else if (!dkim.length) {
        const known = provider && ["google", "microsoft", "zoho", "proton"].includes(provider);
        add({ area: "DKIM", severity: known ? "high" : "medium", id: "dkim_missing", title: known ? `DKIM isn't set up for ${PROVIDERS[provider].name}` : "No DKIM key found on common selectors", detail: known ? `${PROVIDERS[provider].name} signs with the selector ${PROVIDERS[provider].selectors.join(" / ")}, and no key is published there. Gmail and Yahoo now expect DKIM from every sender.` : `We tried ${selectors.length} common selectors. If your provider uses a custom one, enter it above and check again. Without DKIM, Gmail and Yahoo are much more likely to reject or spam-folder your mail.` });
      } else {
        const known = provider && ["google", "microsoft", "zoho", "proton"].includes(provider);
        if (known && !dkim.some((k) => !k.revoked && PROVIDERS[provider].selectors.includes(k.selector)))
          add({ area: "DKIM", severity: "high", id: "dkim_provider_missing", title: `DKIM isn't set up for ${PROVIDERS[provider].name}`, detail: `There's a DKIM key for another service (${dkim.map((k) => k.selector).join(", ")}), but none for ${PROVIDERS[provider].name} (selector ${PROVIDERS[provider].selectors.join(" / ")}). Mail you send from ${PROVIDERS[provider].name} itself goes out unsigned.` });
        for (const k of dkim) {
          if (k.revoked) add({ area: "DKIM", severity: "low", title: `DKIM selector "${k.selector}" is revoked`, detail: "The key is empty (p=), which is how a retired key is switched off. Fine if nothing still signs with it." });
          else if (k.bits === 1024) add({ area: "DKIM", severity: "medium", id: "dkim_1024", title: `DKIM key "${k.selector}" is 1024-bit`, detail: "Still accepted, but 2048-bit is the current recommendation. Most providers let you rotate to a 2048-bit key." });
        }
        const good = dkim.filter((k) => !k.revoked);
        if (good.length) add({ area: "DKIM", severity: "pass", title: `DKIM found: ${good.map((k) => k.selector).join(", ")}`, detail: good.map((k) => `${k.selector}: ${k.ed25519 ? "Ed25519" : k.bits + "-bit RSA"}`).join("; ") + "." });
      }
    }

    /* ---- findings: DMARC ---- */
    if (!dmarc) {
      add({ area: "DMARC", severity: "high", id: "dmarc_missing", title: "No DMARC record", detail: sending ? "Gmail and Yahoo require DMARC for bulk senders, and without it spoofed mail using your domain is far more likely to be delivered." : "Without DMARC, receivers have no instruction to reject mail that spoofs this domain." });
    } else {
      const p = (dmarc.p || "").toLowerCase();
      if (!["none", "quarantine", "reject"].includes(p)) add({ area: "DMARC", severity: "high", id: "dmarc_invalid", title: "DMARC record is invalid", detail: `The policy (p=) is ${dmarc.p ? `"${dmarc.p}"` : "missing"}, so receivers ignore the record.` });
      else if (!sending && p !== "reject") add({ area: "DMARC", severity: "medium", id: "dmarc_parked_weak", title: `DMARC policy is ${p} on a domain that doesn't send`, detail: "Domains that never send mail can safely use p=reject, which stops spoofing completely." });
      else if (p === "none") add({ area: "DMARC", severity: "medium", id: "dmarc_none", title: "DMARC policy is none (monitoring only)", detail: "It meets Gmail and Yahoo's minimum, but spoofed mail is still delivered. Move to quarantine once reports show your real mail passing." });
      if (dmarc.pct && Number(dmarc.pct) < 100 && p !== "none") add({ area: "DMARC", severity: "low", title: `DMARC applies to only ${dmarc.pct}% of mail`, detail: "Fine during a rollout; raise to 100 once you're confident." });
      if (!dmarc.rua && sending) add({ area: "DMARC", severity: "medium", id: "dmarc_no_rua", title: "DMARC has no report address (rua)", detail: "You get no reports, so you can't see who sends as your domain or safely tighten the policy." });
      if (inherited) add({ area: "DMARC", severity: "info", title: `Using the DMARC policy of ${orgDomain(domain)}`, detail: "This subdomain has no record of its own, so the parent's policy applies." });
      if (!findings.some((f) => f.area === "DMARC" && f.severity !== "pass" && f.severity !== "info")) add({ area: "DMARC", severity: "pass", title: `DMARC policy: ${p}`, detail: dmarcRecs[0] });
    }

    /* ---- blocklists ---- */
    const ips = new Set();
    if (spf) for (const v of spf.ip4) { const ip = isSingleIpv4(v); if (ip) ips.add(ip); }
    if (provider === "mailcow") {
      for (const m of mx.slice(0, 2)) {
        const a = await resolve(m.host, "A");
        a.records.slice(0, 1).forEach((ip) => ips.add(ip));
      }
    }
    const ipList = [...ips].slice(0, 4);
    const listings = [], unknown = new Set();
    await Promise.all([
      ...ipList.flatMap((ip) => IP_BLOCKLISTS.map(async (l) => {
        const s = await checkList(reverseIp(ip), l, resolve);
        if (s === "listed") listings.push({ target: ip, list: l });
        if (s === "unknown") unknown.add(l.name);
      })),
      ...DOMAIN_BLOCKLISTS.map(async (l) => {
        const s = await checkList(domain, l, resolve);
        if (s === "listed") listings.push({ target: domain, list: l });
        if (s === "unknown") unknown.add(l.name);
      }),
    ]);
    for (const x of listings) add({ area: "Blocklists", severity: x.list.severe ? "critical" : "high", id: "listed", title: `${x.target} is listed on ${x.list.name}`, detail: x.list.severe ? "Many receivers reject mail from listed senders outright. Find and stop the cause (a compromised account, a bad list), then request delisting." : "Some receivers use this list to filter mail. Fix the cause, then request removal." });
    if (!listings.length) add({ area: "Blocklists", severity: "pass", title: "Not found on the blocklists we checked", detail: `${ipList.length ? `Checked ${ipList.join(", ")} and the domain.` : "Checked the domain."}${unknown.size ? ` ${[...unknown].join(", ")} refused to answer public resolvers, so those weren't checked.` : ""}` });
    facts.blocklists = { checkedIps: ipList, listings, unknown: [...unknown] };

    /* ---- MTA-STS / TLS-RPT ---- */
    if (mx.length && !nullMx) {
      const [sts, rpt] = await Promise.all([resolve(`_mta-sts.${domain}`, "TXT"), resolve(`_smtp._tls.${domain}`, "TXT")]);
      const hasSts = sts.records.some((t) => /^v=STSv1/i.test(t));
      const hasRpt = rpt.records.some((t) => /^v=TLSRPTv1/i.test(t));
      if (!hasSts || !hasRpt) add({ area: "Transport", severity: "info", title: `${[!hasSts && "MTA-STS", !hasRpt && "TLS-RPT"].filter(Boolean).join(" and ")} not set up`, detail: "Optional hardening that forces encrypted delivery to your mail servers and reports failures." });
      else add({ area: "Transport", severity: "pass", title: "MTA-STS and TLS-RPT are set up", detail: "Inbound mail delivery is protected against downgrade attacks." });
    }

    /* combined: nothing at all */
    if (sending && !spfRecords.length && !dmarc) {
      add({ area: "SPF", severity: "critical", id: "no_auth", title: "No SPF and no DMARC", detail: "Your mail has no authentication at all. Expect heavy spam-foldering, and anyone can impersonate the domain." });
    }

    const order = ["critical", "high", "medium", "low", "info", "pass"];
    findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
    const counts = Object.fromEntries(order.map((s) => [s, findings.filter((f) => f.severity === s).length]));
    return {
      tool: "derops-email-check", version: VERSION, checked_at: new Date().toISOString(),
      domain, facts, findings, counts, grade: gradeOf(counts),
      fixes: buildFixes(facts, findings, opts.fixProvider !== undefined ? opts.fixProvider : provider),
    };
  }

  function gradeOf(c) {
    if (c.critical > 0) return "F";
    if (c.high >= 2) return "D";
    if (c.high === 1) return "C";
    if (c.medium > 0) return "B";
    return "A";
  }

  /* --------------------------------------------------------------- fixes */

  function mergeSpf(existingRecords, providerTerm, keepHardFail) {
    const terms = [];
    const seen = new Set();
    let hard = keepHardFail;
    for (const rec of existingRecords) {
      for (const t of parseSpf(rec)) {
        if (t.name === "all" && !t.modifier) { if (t.qualifier === "-") hard = true; continue; }
        if (t.modifier && t.name === "redirect") continue;
        const key = t.raw.replace(/^\+/, "").toLowerCase();
        if (!seen.has(key)) { seen.add(key); terms.push(t.raw.replace(/^\+/, "")); }
      }
    }
    if (providerTerm && !seen.has(providerTerm.toLowerCase())) terms.unshift(providerTerm);
    return ["v=spf1", ...terms, hard ? "-all" : "~all"].join(" ");
  }

  function buildFixes(facts, findings, providerKey) {
    const d = facts.domain;
    const has = (id) => findings.some((f) => f.id === id);
    const p = providerKey ? PROVIDERS[providerKey] : null;
    const fixes = [];

    if (!facts.sending) {
      if (!facts.spf.records.length || facts.spf.all !== "-")
        fixes.push({ title: "Block all mail claiming to be from this domain", type: "TXT", host: d, value: "v=spf1 -all" });
      if (!facts.dmarc.tags || (facts.dmarc.tags.p || "").toLowerCase() !== "reject")
        fixes.push({ title: "Tell receivers to reject spoofed mail", type: "TXT", host: `_dmarc.${d}`, value: "v=DMARC1; p=reject;" });
      if (!facts.mx.length) fixes.push({ title: "Optional: declare that the domain accepts no mail (null MX)", type: "MX", host: d, value: "0 ." });
      return fixes;
    }

    // SPF
    const spfBad = has("spf_missing") || has("spf_multiple") || has("spf_plus_all") || has("spf_neutral") || has("spf_no_all") || has("spf_provider_missing") || has("no_auth");
    if (spfBad) {
      const value = mergeSpf(facts.spf.records, p && p.spf, false);
      fixes.push({
        title: facts.spf.records.length ? "Replace your SPF record with this single merged record" : "Add an SPF record",
        type: "TXT", host: d, value,
        note: facts.spf.records.length ? "Keeps every sender you already authorize. Delete the old SPF record(s) when you add this one." : (p ? `Authorizes ${p.name}. Add an include: for any other service that sends as you (newsletter, CRM, helpdesk).` : "Add an include: for each service that sends as you."),
      });
    }
    if (has("spf_too_many_lookups") || has("spf_near_limit")) {
      fixes.push({ title: "Bring SPF under 10 lookups", note: "Remove includes for tools you no longer use, move bulk or marketing mail to a subdomain (for example news." + d + ") with its own SPF, or replace includes with the provider's ip4: ranges where they publish them." });
    }

    // DKIM
    if (has("dkim_missing") || has("dkim_provider_missing")) {
      const steps = {
        google: { note: "Google Admin console: Apps, Google Workspace, Gmail, Authenticate email. Generate a 2048-bit key, publish the TXT record it shows, then click Start authentication.", host: `google._domainkey.${d}`, type: "TXT", value: "(the v=DKIM1; k=rsa; p=… value Google shows you)" },
        microsoft: { note: "Microsoft Defender portal: Email & collaboration, Policies, Email authentication settings, DKIM. Select the domain, publish the two CNAME records it shows, then enable signing.", host: `selector1._domainkey.${d} and selector2._domainkey.${d}`, type: "CNAME", value: "(the two targets shown in the Defender portal)" },
        zoho: { note: "Zoho Mail Admin Console: Domains, your domain, Email Configuration, DKIM. Add a selector, publish the TXT record, then verify.", host: `zoho._domainkey.${d}`, type: "TXT", value: "(the value Zoho shows you)" },
        proton: { note: "Proton: Settings, Domain names, Review, DKIM. Publish the three CNAME records shown.", host: `protonmail._domainkey.${d} (+2 more)`, type: "CNAME", value: "(the targets Proton shows you)" },
        mailcow: { note: "Mailcow UI: Configuration, ARC/DKIM keys. Generate a 2048-bit key for the domain with selector dkim, then publish it.", host: `dkim._domainkey.${d}`, type: "TXT", value: "(the v=DKIM1; k=rsa; p=… value Mailcow shows you)" },
      };
      const s = steps[providerKey] || { note: "In your email provider's admin panel, find the DKIM (domain authentication) settings, generate a 2048-bit key and publish the record it gives you." };
      fixes.push({ title: `Set up DKIM${p ? ` for ${p.name}` : ""}`, ...s });
    }
    for (const k of (facts.dkim.found || []).filter((k) => k.bits === 1024)) {
      const own = p && p.selectors.includes(k.selector);
      fixes.push({
        title: `Rotate DKIM key "${k.selector}" to 2048-bit`,
        note: own
          ? `Generate a new 2048-bit key in ${p.name}'s DKIM settings, publish it at ${k.selector}._domainkey.${d}, then switch signing to it.`
          : `This selector belongs to one of your sending services${k.selector === "s1" || k.selector === "s2" ? " (s1/s2 are usually SendGrid)" : ""}. Regenerate the key in that service's domain authentication settings and update the record it gives you.`,
      });
    }

    // DMARC
    const rua = `mailto:dmarc@${d}`;
    if (has("dmarc_missing") || has("dmarc_invalid") || has("no_auth")) {
      fixes.push({ title: "Add a DMARC record (start in monitoring mode)", type: "TXT", host: `_dmarc.${d}`, value: `v=DMARC1; p=none; rua=${rua}; fo=1`, note: `Create the dmarc@${d} mailbox (or use a DMARC report service) first. After 2 to 4 weeks of reports showing your real mail passing, move to p=quarantine.` });
    } else if (facts.dmarc.tags) {
      const t = facts.dmarc.tags;
      const p0 = (t.p || "").toLowerCase();
      if (has("dmarc_none") || has("dmarc_no_rua")) {
        const nextP = p0 === "none" && t.rua ? "quarantine" : p0 || "none";
        const parts = [`v=DMARC1; p=${nextP}`, `rua=${t.rua || rua}`];
        if (t.ruf) parts.push(`ruf=${t.ruf}`);
        if (t.sp) parts.push(`sp=${t.sp}`);
        parts.push("fo=1");
        fixes.push({ title: nextP === "quarantine" ? "Tighten DMARC to quarantine" : "Add a report address to DMARC", type: "TXT", host: facts.dmarc.host, value: parts.join("; "), note: nextP === "quarantine" ? "Only do this once your reports show all legitimate mail passing SPF or DKIM." : `Create the dmarc@${d} mailbox (or use a DMARC report service) so the reports have somewhere to go.` });
      }
    }
    return fixes;
  }

  return { VERSION, check, gradeOf, dohResolver, parseTxtData, parseSpf, mergeSpf, normalizeDomain, orgDomain, PROVIDERS };
})();

if (typeof module !== "undefined" && module.exports) module.exports = EmailCheck;
