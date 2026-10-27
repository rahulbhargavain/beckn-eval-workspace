"use strict";
(function () {
  var MAX_BYTES = 5 * 1024 * 1024;
  var out = document.getElementById("out");
  var errBox = document.getElementById("error");
  var drop = document.getElementById("drop");

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function showError(msg) {
    out.hidden = true;
    errBox.textContent = msg;
    errBox.hidden = false;
  }

  function render(v) {
    errBox.hidden = true;
    out.replaceChildren();

    var head = el("div", "card");
    head.appendChild(el("span", "badge " + v.verdict, v.verdict));
    head.appendChild(el("span", null, "  " + v.counts.pass + " pass, " + v.counts.fail + " fail, " +
      v.counts.pending + " pending" + (v.counts.unknown ? ", " + v.counts.unknown + " unknown" : "")));
    if (!v.consistent) {
      head.appendChild(el("div", "alert", "Verdict " + v.verdict + " does not match the results, which derive " +
        v.derivedVerdict + ". Do not trust this report."));
    }
    if (v.probe) head.appendChild(el("div", "alert", "Probe run: a subset of scenarios, never certifiable."));
    head.appendChild(el("div", null, v.signatureNote));
    var dl = el("dl");
    [["Participant", v.participant], ["Profile", v.profile], ["Spec", v.spec], ["Role", v.role],
     ["Target", v.baseUrl], ["Issued", v.issuedAt], ["Runner", v.runnerVersion],
     ["Harness key", v.harnessKeyId], ["Digest", v.digest]].forEach(function (p) {
      dl.appendChild(el("dt", null, p[0]));
      dl.appendChild(el("dd", p[0] === "Digest" || p[0] === "Harness key" ? "mono" : null, p[1] || "-"));
    });
    head.appendChild(dl);
    out.appendChild(head);

    [["Problems", v.problems], ["Warnings", v.warnings]].forEach(function (g) {
      if (!g[1].length) return;
      var c = el("div", "card");
      c.appendChild(el("strong", null, g[0]));
      var ul = el("ul");
      g[1].forEach(function (s) { ul.appendChild(el("li", null, s)); });
      c.appendChild(ul);
      out.appendChild(c);
    });

    var wrap = el("div", "card scroll");
    var t = el("table");
    var hr = el("tr");
    ["Scenario", "Level", "Outcome", "Detail", "Pinned hash"].forEach(function (h) { hr.appendChild(el("th", null, h)); });
    t.appendChild(hr);
    v.rows.forEach(function (r) {
      var tr = el("tr");
      tr.appendChild(el("td", "mono", r.id));
      tr.appendChild(el("td", null, r.level));
      tr.appendChild(el("td", r.outcome, r.outcome));
      tr.appendChild(el("td", null, r.detail));
      tr.appendChild(el("td", "mono", r.hash ? r.hash.slice(0, 16) : "-"));
      t.appendChild(tr);
    });
    wrap.appendChild(t);
    out.appendChild(wrap);
    out.hidden = false;
  }

  function load(file) {
    if (!file) return;
    if (file.size > MAX_BYTES) return showError("File is larger than 5 MB.");
    var reader = new FileReader();
    reader.onerror = function () { showError("Could not read the file."); };
    reader.onload = function () {
      var data;
      try { data = JSON.parse(String(reader.result)); } catch (e) { return showError("Not valid JSON."); }
      var v = ReportView.summarize(data);
      if (!v.ok) return showError(v.error);
      render(v);
    };
    reader.readAsText(file);
  }

  document.getElementById("file").addEventListener("change", function (e) { load(e.target.files[0]); });
  drop.addEventListener("dragover", function (e) { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", function () { drop.classList.remove("over"); });
  drop.addEventListener("drop", function (e) {
    e.preventDefault(); drop.classList.remove("over");
    load(e.dataTransfer.files[0]);
  });
})();
