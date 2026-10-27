"use strict";
// Pure view-model for a conformance report. No DOM, no network. The viewer only
// displays; it never verifies the signature (that is conformance.runner.admit's job).
(function (root) {
  var OUTCOMES = ["pass", "fail", "pending"];
  var VERDICTS = ["CERTIFIED", "FAILED", "INCOMPLETE"];

  function fail(error) { return { ok: false, error: error }; }

  function derive(report, rows) {
    var mandFail = false, mandPending = false;
    rows.forEach(function (r) {
      if (r.level !== "mandatory") return;
      if (r.outcome === "fail") mandFail = true;
      if (r.outcome === "pending" || r.outcome === "unknown") mandPending = true;
    });
    var hasMandatory = rows.some(function (r) { return r.level === "mandatory"; });
    var problems = Array.isArray(report.problems) ? report.problems : [];
    if (mandFail) return "FAILED";
    if (mandPending || problems.length || report.probe || !hasMandatory) return "INCOMPLETE";
    return "CERTIFIED";
  }

  function summarize(report) {
    if (!report || typeof report !== "object" || Array.isArray(report)) return fail("report is not an object");
    if (!Array.isArray(report.results)) return fail("report has no results array");
    var hashes = report.scenario_hashes && typeof report.scenario_hashes === "object" ? report.scenario_hashes : {};
    var counts = { pass: 0, fail: 0, pending: 0, unknown: 0 };
    var rows = [];
    for (var i = 0; i < report.results.length; i++) {
      var r = report.results[i];
      if (!r || typeof r !== "object" || Array.isArray(r)) return fail("result " + i + " is not an object");
      var outcome = OUTCOMES.indexOf(r.outcome) >= 0 ? r.outcome : "unknown";
      counts[outcome] += 1;
      rows.push({
        id: String(r.id), level: String(r.level), outcome: outcome,
        detail: r.detail == null ? "" : String(r.detail),
        hash: hashes[r.id] == null ? "" : String(hashes[r.id]),
      });
    }
    var verdict = VERDICTS.indexOf(report.verdict) >= 0 ? report.verdict : "UNKNOWN";
    var derivedVerdict = derive(report, rows);
    var issued = typeof report.issued_at === "number" && isFinite(report.issued_at)
      ? new Date(report.issued_at * 1000).toISOString() : "";
    return {
      ok: true,
      verdict: verdict,
      derivedVerdict: derivedVerdict,
      consistent: verdict === derivedVerdict,
      participant: String(report.participant == null ? "" : report.participant),
      profile: String(report.profile == null ? "" : report.profile),
      spec: String(report.spec == null ? "" : report.spec),
      role: String(report.role == null ? "" : report.role),
      baseUrl: String(report.base_url == null ? "" : report.base_url),
      harnessKeyId: String(report.harness_key_id == null ? "" : report.harness_key_id),
      runnerVersion: String(report.runner_version == null ? "" : report.runner_version),
      digest: String(report.digest == null ? "" : report.digest),
      issuedAt: issued,
      probe: report.probe === true,
      problems: (Array.isArray(report.problems) ? report.problems : []).map(String),
      warnings: (Array.isArray(report.warnings) ? report.warnings : []).map(String),
      signaturePresent: !!report.signature,
      signatureVerified: false,
      signatureNote: report.signature
        ? "Signature present but not verified here. Verify with conformance.runner.admit and the operator's public key."
        : "No signature: this report can never be admitted.",
      counts: counts,
      rows: rows,
    };
  }

  var api = { summarize: summarize };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.ReportView = api;
})(typeof self !== "undefined" ? self : this);
