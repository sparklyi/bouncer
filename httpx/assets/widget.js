// bouncer widget: drop-in browser check.
//
//   <script src="/_bouncer/widget.js" defer></script>
//
// On load it silently solves a proof of work and stores a short-lived pass
// cookie. Single-page apps can await window.bouncer.verify() before a request
// that the server protects.
(function () {
  "use strict";

  var script = document.currentScript;
  var base = (script && script.dataset.base) || "/_bouncer";
  var auto = !(script && script.dataset.auto === "false");
  var inflight = null;

  function requestChallenge() {
    return fetch(base + "/challenge", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
      credentials: "same-origin",
    }).then(function (response) {
      if (!response.ok) throw new Error("bouncer: challenge failed");
      return response.json();
    });
  }

  function solve(params) {
    return new Promise(function (resolve, reject) {
      if (params.alg !== "sha256") return reject(new Error("bouncer: unsupported algorithm"));
      if (params.degree > 24) return reject(new Error("bouncer: difficulty above budget"));
      var worker;
      try {
        worker = new Worker(base + "/worker.js");
      } catch (error) {
        return reject(error);
      }
      worker.onmessage = function (event) {
        worker.terminate();
        resolve(event.data.answer);
      };
      worker.onerror = function (error) {
        worker.terminate();
        reject(error);
      };
      worker.postMessage({ salt: params.salt, degree: params.degree });
    });
  }

  function exchange(token, answer) {
    return fetch(base + "/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: token, answer: answer }),
      credentials: "same-origin",
    }).then(function (response) {
      if (!response.ok) throw new Error("bouncer: verification failed");
      return response.json();
    });
  }

  function verify() {
    if (inflight) return inflight;
    inflight = requestChallenge()
      .then(function (challenge) {
        return solve(challenge.params).then(function (answer) {
          return exchange(challenge.token, answer);
        });
      })
      .then(
        function (result) {
          inflight = null;
          document.dispatchEvent(new CustomEvent("bouncer:verified", { detail: result }));
          return result;
        },
        function (error) {
          inflight = null;
          throw error;
        }
      );
    return inflight;
  }

  var api = {
    verify: verify,
    ready: null,
    base: base,
  };
  Object.defineProperty(window, "bouncer", { value: api, writable: false, configurable: true });

  if (auto) {
    api.ready = verify().catch(function () {
      // A failed silent check is not fatal: the server answers 403 with an
      // interstitial that retries in the foreground.
      return null;
    });
  }
})();
