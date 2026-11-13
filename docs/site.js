// Drives the simulated ledger on the homepage. Purely illustrative: no network,
// no storage. Without JS (or with reduced motion) the static table stands in.
(function () {
  "use strict";

  var demo = document.getElementById("demo");
  if (!demo || matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  var bar = demo.querySelector(".incoming");
  var incoming = document.getElementById("incoming");
  var verdict = document.getElementById("verdict");
  var rows = document.getElementById("rows");
  var tally = {
    recv: document.getElementById("t-recv"),
    drop: document.getElementById("t-drop"),
    keys: document.getElementById("t-keys"),
    mail: document.getElementById("t-mail")
  };

  var NOISE = [
    ["script-src · chrome-extension://kbfnbcaeplbc…", "dropped · scheme"],
    ["script-src-elem · moz-extension://5d0c1a…/inject.js", "dropped · scheme"],
    ["style-src · safari-web-extension://a91f…", "dropped · scheme"],
    ["connect-src · https://translate.googleapis.com", "dropped · host rule"],
    ["script-src · https://av-proxy.example/inject.js", "dropped · host rule"],
    ["document-uri · https://scanner.example/probe", "dropped · not your domain"],
    ["worker-src · blob", "dropped · not in your policy"],
    ["font-src · chrome-extension://gighmmpiobkl…", "dropped · scheme"]
  ];
  var REPEATS = [
    ["img", "img-src · https://images.old-cdn.example"],
    ["img", "img-src · https://images.old-cdn.example"],
    ["script", "script-src · https://widgets.example/embed.js"],
    ["font", "font-src · https://fonts.example"],
    ["connect", "connect-src · https://api.example"]
  ];
  // New keys are rare by design; once these are used up the ledger just
  // keeps eating noise, which is what most days look like.
  var FRESH = [
    { at: 9, key: "frame", directive: "frame-src", blocked: "https://checkout.example" },
    { at: 46, key: "media", directive: "media-src", blocked: "https://video.example" }
  ];

  var tick = 0, timer = null, visible = false;

  function num(el) { return parseInt(el.textContent.replace(/\D/g, ""), 10) || 0; }
  function inc(el) { el.textContent = (num(el) + 1).toLocaleString("en-US"); }
  function pick(list) { return list[Math.floor(Math.random() * list.length)]; }
  function replay(el, cls) { el.classList.remove(cls); void el.offsetWidth; el.classList.add(cls); }

  function cell(cls, text) {
    var td = document.createElement("td");
    if (cls) td.className = cls;
    if (text) td.textContent = text;
    return td;
  }

  function addRow(f) {
    var tr = document.createElement("tr");
    tr.dataset.key = f.key;
    var d = cell("d");
    var dot = document.createElement("i");
    dot.className = "dot new";
    d.appendChild(dot);
    var blocked = cell("mono", f.blocked);
    var tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = "new";
    blocked.appendChild(tag);
    tr.append(d, cell("mono", f.directive), blocked, cell("num", "1"));
    // Below the unattributed-inline row, above the quiet ones.
    rows.insertBefore(tr, rows.children[1]);
    tr.classList.add("enter");
    REPEATS.push([f.key, f.directive + " · " + f.blocked]);
  }

  function step() {
    tick += 1;
    var fresh = FRESH.find(function (f) { return f.at === tick; });
    var kind, text, label, target;

    if (fresh) {
      kind = "new"; text = fresh.directive + " · " + fresh.blocked; label = "new key · goes in the digest";
    } else if (Math.random() < 0.62) {
      var n = pick(NOISE);
      kind = "drop"; text = n[0]; label = n[1];
    } else {
      var r = pick(REPEATS);
      kind = "repeat"; text = r[1]; label = "seen before · count +1";
      target = rows.querySelector('[data-key="' + r[0] + '"]');
    }

    bar.classList.remove("judged", "drop", "repeat", "new");
    incoming.textContent = text;
    verdict.textContent = label;
    replay(bar, "fresh");
    inc(tally.recv);

    setTimeout(function () {
      bar.classList.add("judged", kind);
      if (kind === "drop") {
        inc(tally.drop);
      } else if (kind === "new") {
        addRow(fresh);
        inc(tally.keys);
        inc(tally.mail);
      } else if (target) {
        inc(target.querySelector(".num"));
        replay(target, "bump");
      }
    }, 420);
  }

  function sync() {
    var run = visible && !document.hidden;
    if (run && !timer) timer = setInterval(step, 1150);
    if (!run && timer) { clearInterval(timer); timer = null; }
  }

  new IntersectionObserver(function (entries) {
    visible = entries[0].isIntersecting;
    sync();
  }, { threshold: 0.15 }).observe(demo);
  document.addEventListener("visibilitychange", sync);
})();
