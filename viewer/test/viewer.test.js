"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { summarize } = require("../render.js");

const base = () => ({
  participant: "p", profile: "ds-core", spec: "beckn-2.0.0", role: "DS", issued_at: 1700000000,
  runner_version: "2", base_url: "https://n.example", harness_key_id: "k", probe: false,
  verdict: "CERTIFIED", warnings: [], problems: [], scenario_hashes: { A: "h1", B: "h2" },
  results: [{ id: "A", level: "mandatory", outcome: "pass", detail: "" },
            { id: "B", level: "recommended", outcome: "pass", detail: "" }],
  digest: "d", signature: "s",
});

test("summarizes a clean report", () => {
  const v = summarize(base());
  assert.equal(v.ok, true);
  assert.equal(v.verdict, "CERTIFIED");
  assert.equal(v.consistent, true);
  assert.deepEqual(v.counts, { pass: 2, fail: 0, pending: 0, unknown: 0 });
  assert.equal(v.issuedAt, "2023-11-14T22:13:20.000Z");
  assert.equal(v.signaturePresent, true);
  assert.equal(v.rows[0].hash, "h1");
});

test("never claims the signature was verified", () => {
  const v = summarize(base());
  assert.equal(v.signatureVerified, false);
  assert.match(v.signatureNote, /not verified/i);
});

test("flags a CERTIFIED verdict that the results contradict", () => {
  const r = base();
  r.results[0].outcome = "fail";
  const v = summarize(r);
  assert.equal(v.verdict, "CERTIFIED");
  assert.equal(v.derivedVerdict, "FAILED");
  assert.equal(v.consistent, false);
});

test("probe or problems can never derive CERTIFIED", () => {
  const p = base(); p.probe = true;
  assert.equal(summarize(p).derivedVerdict, "INCOMPLETE");
  const q = base(); q.problems = ["x"];
  assert.equal(summarize(q).derivedVerdict, "INCOMPLETE");
});

test("recommended failure does not fail the verdict", () => {
  const r = base(); r.results[1].outcome = "fail";
  assert.equal(summarize(r).derivedVerdict, "CERTIFIED");
});

test("mandatory pending is incomplete", () => {
  const r = base(); r.results[0].outcome = "pending";
  assert.equal(summarize(r).derivedVerdict, "INCOMPLETE");
});

test("unknown outcome and unknown verdict are surfaced, not trusted", () => {
  const r = base(); r.results[0].outcome = "weird"; r.verdict = "GREAT";
  const v = summarize(r);
  assert.equal(v.counts.unknown, 1);
  assert.equal(v.verdict, "UNKNOWN");
  assert.equal(v.consistent, false);
});

test("malformed input is rejected without throwing", () => {
  for (const bad of [null, undefined, 5, "x", [], {}, { results: "no" }, { results: [1] }]) {
    const v = summarize(bad);
    assert.equal(v.ok, false);
    assert.ok(v.error);
  }
});

test("long and hostile strings are passed through as plain data", () => {
  const r = base(); r.participant = "<img src=x onerror=alert(1)>";
  const v = summarize(r);
  assert.equal(v.participant, "<img src=x onerror=alert(1)>");
});

test("does not reveal a private seed if one is present by mistake", () => {
  const r = base(); r.private_key_seed_b64 = "SECRETSEED";
  assert.ok(!JSON.stringify(summarize(r)).includes("SECRETSEED"));
});

const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
const js = fs.readFileSync(path.join(__dirname, "..", "render.js"), "utf8");

test("page is self-contained: no remote scripts, styles or fetches", () => {
  assert.ok(!/(src|href)\s*=\s*["']https?:/i.test(html));
  assert.ok(!/\b(fetch|XMLHttpRequest|WebSocket|sendBeacon)\b/.test(html + js));
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /connect-src 'none'/);
});

test("page never uses innerHTML, eval or document.write", () => {
  for (const s of [html, js]) assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|eval\(|new Function|document\.write/.test(s));
});
