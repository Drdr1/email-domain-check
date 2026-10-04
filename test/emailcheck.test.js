// Run with: node --test test/
const test = require("node:test");
const assert = require("node:assert/strict");
const EC = require("../src/emailcheck.js");

const KEY2048 = "MIIB" + "A".repeat(388);   // ~294 bytes of key material
const KEY1024 = "MIGf" + "A".repeat(212);   // ~162 bytes

// Fake DNS: "name|TYPE" -> array of records, "NX" or "ERR". Anything missing is NXDOMAIN.
function fakeResolver(zone) {
  return async (name, type) => {
    const v = zone[`${name.toLowerCase()}|${type}`];
    if (v === "ERR") return { status: "error", records: [], error: "SERVFAIL" };
    if (!v || v === "NX") return { status: "nxdomain", records: [] };
    return { status: "ok", records: v };
  };
}
const ids = (r) => r.findings.filter((f) => f.id).map((f) => f.id).sort();
const sev = (r, s) => r.findings.filter((f) => f.severity === s).map((f) => f.title);

const GOOGLE_SPF = {
  "_spf.google.com|TXT": ["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"],
  "_netblocks.google.com|TXT": ["v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ~all"],
  "_netblocks2.google.com|TXT": ["v=spf1 ip6:2001:4860:4000::/36 ~all"],
  "_netblocks3.google.com|TXT": ["v=spf1 ip4:172.217.0.0/19 ~all"],
};

test("well configured Google Workspace domain gets an A and no fixes", async () => {
  const r = await EC.check("good-google.com", { resolve: fakeResolver({
    ...GOOGLE_SPF,
    "good-google.com|MX": ["1 aspmx.l.google.com.", "5 alt1.aspmx.l.google.com."],
    "good-google.com|TXT": ["google-site-verification=abc", "v=spf1 include:_spf.google.com -all"],
    "google._domainkey.good-google.com|TXT": [`v=DKIM1; k=rsa; p=${KEY2048}`],
    "_dmarc.good-google.com|TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@good-google.com"],
    "_mta-sts.good-google.com|TXT": ["v=STSv1; id=1"],
    "_smtp._tls.good-google.com|TXT": ["v=TLSRPTv1; rua=mailto:tls@good-google.com"],
  }) });
  assert.equal(r.facts.provider, "google");
  assert.equal(r.facts.spf.lookups, 4);
  assert.deepEqual(r.facts.spf.senders, ["Google Workspace"]);
  assert.equal(r.grade, "A", JSON.stringify(r.findings, null, 1));
  assert.equal(r.fixes.length, 0);
});

test("Microsoft 365 with DMARC p=none gets a B and a quarantine suggestion", async () => {
  const r = await EC.check("contoso-example.com", { resolve: fakeResolver({
    "contoso-example.com|MX": ["0 contoso-example-com.mail.protection.outlook.com."],
    "contoso-example.com|TXT": ["v=spf1 include:spf.protection.outlook.com -all"],
    "spf.protection.outlook.com|TXT": ["v=spf1 ip4:40.92.0.0/15 ip4:52.100.0.0/14 -all"],
    "selector1._domainkey.contoso-example.com|TXT": [`v=DKIM1; k=rsa; p=${KEY2048}`],
    "_dmarc.contoso-example.com|TXT": ["v=DMARC1; p=none; rua=mailto:reports@contoso-example.com"],
  }) });
  assert.equal(r.facts.provider, "microsoft");
  assert.deepEqual(ids(r), ["dmarc_none"]);
  assert.equal(r.grade, "B");
  const fix = r.fixes.find((f) => f.host === "_dmarc.contoso-example.com");
  assert.equal(fix.value, "v=DMARC1; p=quarantine; rua=mailto:reports@contoso-example.com; fo=1");
});

test("two SPF records is critical, and the fix merges both into one", async () => {
  const r = await EC.check("broken.example", { resolve: fakeResolver({
    "broken.example|MX": ["1 aspmx.l.google.com."],
    "broken.example|TXT": ["v=spf1 include:sendgrid.net ~all", "v=spf1 include:servers.mcsv.net ?all"],
    "sendgrid.net|TXT": ["v=spf1 ip4:167.89.0.0/17 ~all"],
    "servers.mcsv.net|TXT": ["v=spf1 ip4:205.201.128.0/20 ~all"],
  }) });
  assert.equal(r.grade, "F");
  assert.ok(ids(r).includes("spf_multiple"));
  assert.ok(!ids(r).includes("spf_broken_include"), "multiple records reported once, not twice");
  assert.ok(ids(r).includes("spf_provider_missing"));
  assert.ok(ids(r).includes("dkim_missing"));
  assert.ok(ids(r).includes("dmarc_missing"));
  const spfFix = r.fixes.find((f) => f.host === "broken.example" && f.type === "TXT");
  assert.equal(spfFix.value, "v=spf1 include:_spf.google.com include:sendgrid.net include:servers.mcsv.net ~all");
  assert.ok(r.fixes.some((f) => f.host === "google._domainkey.broken.example"));
  assert.ok(r.fixes.some((f) => f.host === "_dmarc.broken.example" && /p=none/.test(f.value)));
});

test("more than 10 SPF lookups is critical", async () => {
  const zone = {
    "busy.example|MX": ["10 mail.busy.example."],
    "mail.busy.example|A": ["198.51.100.20"],
    "dkim._domainkey.busy.example|TXT": [`v=DKIM1; k=rsa; p=${KEY2048}`],
    "_dmarc.busy.example|TXT": ["v=DMARC1; p=quarantine; rua=mailto:d@busy.example"],
  };
  const incs = [];
  for (let i = 1; i <= 11; i++) { incs.push(`include:s${i}.vendor.example`); zone[`s${i}.vendor.example|TXT`] = [`v=spf1 ip4:192.0.2.${i} ~all`]; }
  zone["busy.example|TXT"] = [`v=spf1 ${incs.join(" ")} ~all`];
  const r = await EC.check("busy.example", { resolve: fakeResolver(zone) });
  assert.equal(r.facts.spf.lookups, 11);
  assert.ok(ids(r).includes("spf_too_many_lookups"));
  assert.equal(r.grade, "F");
  assert.ok(r.fixes.some((f) => /under 10 lookups/.test(f.title)));
});

test("a parked domain is judged on spoofing protection, with parked-domain fixes", async () => {
  const r = await EC.check("parked.example", { resolve: fakeResolver({}) });
  assert.equal(r.facts.sending, false);
  assert.deepEqual(ids(r), ["dmarc_missing", "spf_missing"]);
  assert.equal(r.grade, "D");
  assert.deepEqual(r.fixes.map((f) => f.value), ["v=spf1 -all", "v=DMARC1; p=reject;", "0 ."]);
});

test("a correctly locked parked domain gets an A", async () => {
  const r = await EC.check("locked.example", { resolve: fakeResolver({
    "locked.example|MX": ["0 ."],
    "locked.example|TXT": ["v=spf1 -all"],
    "_dmarc.locked.example|TXT": ["v=DMARC1; p=reject;"],
  }) });
  assert.equal(r.facts.nullMx, true);
  assert.equal(r.facts.sending, false);
  assert.equal(r.grade, "A", JSON.stringify(r.findings, null, 1));
});

test("self-hosted Mailcow: blocklist hit is reported, refused lists are 'couldn't check'", async () => {
  const r = await EC.check("selfhost.example", { resolve: fakeResolver({
    "selfhost.example|MX": ["10 mail.selfhost.example."],
    "mail.selfhost.example|A": ["203.0.113.5"],
    "selfhost.example|TXT": ["v=spf1 mx ~all"],
    "dkim._domainkey.selfhost.example|TXT": [`v=DKIM1; k=rsa; p=${KEY2048}`],
    "_dmarc.selfhost.example|TXT": ["v=DMARC1; p=quarantine; rua=mailto:d@selfhost.example"],
    "5.113.0.203.zen.spamhaus.org|A": ["127.255.255.254"],
    "5.113.0.203.bl.spamcop.net|A": ["127.0.0.2"],
    "selfhost.example.dbl.spamhaus.org|A": ["127.255.255.254"],
  }) });
  assert.equal(r.facts.provider, "mailcow");
  assert.deepEqual(r.facts.blocklists.checkedIps, ["203.0.113.5"]);
  assert.deepEqual(r.facts.blocklists.listings.map((l) => l.list.name), ["SpamCop"]);
  assert.ok(r.facts.blocklists.unknown.includes("Spamhaus ZEN"));
  assert.equal(r.grade, "C");
});

test("1024-bit DKIM key is flagged medium", async () => {
  const r = await EC.check("oldkey.example", { resolve: fakeResolver({
    ...GOOGLE_SPF,
    "oldkey.example|MX": ["1 smtp.google.com."],
    "oldkey.example|TXT": ["v=spf1 include:_spf.google.com ~all"],
    "google._domainkey.oldkey.example|TXT": [`v=DKIM1; k=rsa; p=${KEY1024}`],
    "_dmarc.oldkey.example|TXT": ["v=DMARC1; p=reject; rua=mailto:x@oldkey.example"],
  }) });
  assert.deepEqual(ids(r), ["dkim_1024"]);
  assert.equal(r.grade, "B");
});

test("a custom DKIM selector the user enters is checked", async () => {
  const zone = {
    "custom.example|MX": ["10 mx.custom.example."],
    "mx.custom.example|A": ["198.51.100.7"],
    "custom.example|TXT": ["v=spf1 mx -all"],
    "_dmarc.custom.example|TXT": ["v=DMARC1; p=reject; rua=mailto:d@custom.example"],
    "s2026._domainkey.custom.example|TXT": [`v=DKIM1; k=rsa; p=${KEY2048}`],
  };
  const without = await EC.check("custom.example", { resolve: fakeResolver(zone) });
  assert.ok(ids(without).includes("dkim_missing"));
  const withSel = await EC.check("custom.example", { resolve: fakeResolver(zone), selector: "s2026" });
  assert.ok(!ids(withSel).includes("dkim_missing"));
  assert.equal(withSel.facts.dkim.found[0].selector, "s2026");
});

test("wildcard TXT answers don't count as DKIM keys", async () => {
  const zone = { "wild.example|MX": ["1 aspmx.l.google.com."], "wild.example|TXT": ["v=spf1 include:_spf.google.com ~all"], ...GOOGLE_SPF };
  const base = fakeResolver(zone);
  const resolve = async (n, t) => /\._domainkey\.wild\.example$/.test(n) ? { status: "ok", records: [`v=DKIM1; p=${KEY2048}`] } : base(n, t);
  const r = await EC.check("wild.example", { resolve });
  assert.equal(r.facts.dkim.wildcard, true);
  assert.equal(r.facts.dkim.found.length, 0);
});

test("subdomain inherits the parent's DMARC (sp= applies)", async () => {
  const r = await EC.check("news.parent.co.uk", { resolve: fakeResolver({
    "news.parent.co.uk|TXT": ["v=spf1 include:sendgrid.net -all"],
    "sendgrid.net|TXT": ["v=spf1 ip4:167.89.0.0/17 ~all"],
    "s1._domainkey.news.parent.co.uk|TXT": [`k=rsa; p=${KEY2048}`],
    "_dmarc.parent.co.uk|TXT": ["v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@parent.co.uk"],
  }) });
  assert.equal(r.facts.dmarc.inherited, true);
  assert.equal(r.facts.dmarc.tags.p, "quarantine");
  assert.equal(r.grade, "A", JSON.stringify(r.findings, null, 1));
});

test("a DKIM key for another service doesn't count for the mailbox provider", async () => {
  const r = await EC.check("mixed.example", { resolve: fakeResolver({
    ...GOOGLE_SPF,
    "mixed.example|MX": ["1 aspmx.l.google.com."],
    "mixed.example|TXT": ["v=spf1 include:_spf.google.com include:sendgrid.net ~all"],
    "sendgrid.net|TXT": ["v=spf1 ip4:167.89.0.0/17 ~all"],
    "s1._domainkey.mixed.example|TXT": [`k=rsa; p=${KEY1024}`],
    "_dmarc.mixed.example|TXT": ["v=DMARC1; p=quarantine; rua=mailto:d@mixed.example"],
  }) });
  assert.deepEqual(ids(r), ["dkim_1024", "dkim_provider_missing"]);
  assert.equal(r.grade, "C");
  assert.ok(r.fixes.some((f) => f.host === "google._domainkey.mixed.example"));
  const rot = r.fixes.find((f) => /Rotate DKIM key "s1"/.test(f.title));
  assert.match(rot.note, /SendGrid/);
});

test("an include that points at a name with no SPF is reported as broken", async () => {
  const r = await EC.check("typo.example", { resolve: fakeResolver({
    ...GOOGLE_SPF,
    "typo.example|MX": ["1 aspmx.l.google.com."],
    "typo.example|TXT": ["v=spf1 include:_spf.google.com include:sendgird.net ~all"],
    "google._domainkey.typo.example|TXT": [`v=DKIM1; k=rsa; p=${KEY2048}`],
    "_dmarc.typo.example|TXT": ["v=DMARC1; p=reject; rua=mailto:d@typo.example"],
  }) });
  assert.deepEqual(ids(r), ["spf_broken_include"]);
  assert.match(r.findings.find((f) => f.id === "spf_broken_include").detail, /sendgird\.net has no SPF record/);
});

test("gmail.com-style setup (SPF redirect=, dated DKIM selector) is not penalized", async () => {
  const r = await EC.check("gmail-like.example", { resolve: fakeResolver({
    ...GOOGLE_SPF,
    "gmail-like.example|MX": ["5 gmail-smtp-in.l.google.com.", "10 alt1.gmail-smtp-in.l.google.com."],
    "gmail-like.example|TXT": ["v=spf1 redirect=_spf.google.com"],
    "20230601._domainkey.gmail-like.example|TXT": [`v=DKIM1; k=rsa; p=${KEY2048}`],
    "_dmarc.gmail-like.example|TXT": ["v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com"],
    "_mta-sts.gmail-like.example|TXT": ["v=STSv1; id=1"],
    "_smtp._tls.gmail-like.example|TXT": ["v=TLSRPTv1; rua=mailto:t@google.com"],
  }) });
  assert.ok(r.facts.spf.senders.includes("Google Workspace"));
  assert.deepEqual(ids(r), ["dmarc_none"]);
  assert.equal(r.grade, "B");
});

test("a merged SPF keeps a redirect= as an include", () => {
  assert.equal(EC.mergeSpf(["v=spf1 redirect=_spf.google.com"], "include:_spf.google.com", false), "v=spf1 include:_spf.google.com ~all");
  assert.equal(EC.mergeSpf(["v=spf1 redirect=spf.vendor.example"], "include:_spf.google.com", false), "v=spf1 include:_spf.google.com include:spf.vendor.example ~all");
});

test("an unrecognized selector may be the provider's own, so no high finding", async () => {
  const r = await EC.check("customsel.example", { resolve: fakeResolver({
    ...GOOGLE_SPF,
    "customsel.example|MX": ["1 smtp.google.com."],
    "customsel.example|TXT": ["v=spf1 include:_spf.google.com ~all"],
    "mail._domainkey.customsel.example|TXT": [`v=DKIM1; k=rsa; p=${KEY2048}`],
    "_dmarc.customsel.example|TXT": ["v=DMARC1; p=reject; rua=mailto:d@customsel.example"],
  }) });
  assert.ok(!ids(r).includes("dkim_provider_missing"));
  assert.equal(r.grade, "A", JSON.stringify(r.findings, null, 1));
});

test("DNS failure surfaces a clear error", async () => {
  await assert.rejects(EC.check("x.example", { resolve: fakeResolver({ "x.example|MX": "ERR" }) }), /DNS lookups/);
});

test("domain input is normalized and validated", () => {
  assert.equal(EC.normalizeDomain(" https://www.Example.com/path?x=1 "), "example.com");
  assert.equal(EC.normalizeDomain("ahmed@derops.dev"), "derops.dev");
  assert.equal(EC.normalizeDomain("mail.example.co.uk."), "mail.example.co.uk");
  assert.equal(EC.normalizeDomain("not a domain"), null);
  assert.equal(EC.normalizeDomain("<script>.com"), null);
});

test("TXT data in quoted chunks is joined", () => {
  assert.equal(EC.parseTxtData('"v=spf1 include:a.example " "include:b.example ~all"'), "v=spf1 include:a.example include:b.example ~all");
  assert.equal(EC.parseTxtData("v=spf1 -all"), "v=spf1 -all");
});

test("the DoH resolver parses answers and falls back to the second endpoint", async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    if (url.startsWith("https://dns.google")) return { ok: false, status: 503 };
    return { ok: true, json: async () => ({ Status: 0, Answer: [
      { name: "example.com.", type: 5, data: "alias.example.com." },
      { name: "alias.example.com.", type: 16, data: '"v=spf1 " "-all"' },
    ] }) };
  };
  const resolve = EC.dohResolver(fetchImpl);
  const r = await resolve("example.com", "TXT");
  assert.deepEqual(r, { status: "ok", records: ["v=spf1 -all"] });
  assert.equal(calls.length, 2);
  await resolve("example.com", "TXT");
  assert.equal(calls.length, 2, "second call is cached");
});
