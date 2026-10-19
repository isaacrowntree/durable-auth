/* Two in-page simulations of what durable-auth does. Nothing here talks to a
 * server: the rules are copied from src/server/auth.ts and store.ts so the
 * page behaves the way the library does, and that's all.
 *
 * 1. Step-up: a session that proved its user more than reauthWindowMs ago
 *    gets 403 { reauth: true } from a sensitive route; the client confirms
 *    with a passkey and retries once (the client's withReauth).
 * 2. Recovery caps: 5 guesses a code, 10 wrong guesses a day per email,
 *    5 codes an hour per email. */

(() => {
  const $ = (id) => document.getElementById(id);
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ── step-up ─────────────────────────────────────────────────────── */

  const log = $("reqlog");
  if (log) {
    const WINDOW = 5 * 60; // seconds — reauthWindowMs' default
    const fresh = $("fresh");
    const freshState = $("fresh-state");
    const freshAge = $("fresh-age");
    const freshFill = $("fresh-fill");
    const sheet = $("sheet");
    const buttons = ["act-rename", "act-email", "act-delete", "act-wait"].map($);

    let age = 0; // seconds since the session last proved its user
    let signedIn = true;
    let busy = false;
    let scripted = true;
    let timers = [];
    let answerSheet = null;

    const sleep = (ms) => new Promise((r) => timers.push(setTimeout(r, reduced ? 0 : ms)));

    function renderFresh() {
      const state = !signedIn ? "out" : age > WINDOW ? "stale" : "fresh";
      fresh.dataset.state = state;
      freshState.textContent = state === "out" ? "Signed out" : state === "stale" ? "Stale" : "Fresh";
      const m = Math.floor(age / 60);
      const s = String(age % 60).padStart(2, "0");
      freshAge.textContent = signedIn ? `${m}:${s} ago` : "no session";
      const left = signedIn ? Math.max(0, 1 - age / WINDOW) : 0;
      freshFill.style.transform = `scaleX(${left})`;
      buttons.forEach((b) => (b.disabled = busy || (!signedIn && b.id !== "act-delete")));
      $("act-delete").textContent = signedIn ? "Delete account" : "Start over";
      $("act-delete").classList.toggle("btn--gated", signedIn);
    }

    function line(kind, verb, path, status = "", note = "") {
      const el = document.createElement("div");
      el.className = `req req--${kind}`;
      const v = document.createElement("span");
      v.className = "req__verb";
      v.textContent = verb;
      const p = document.createElement("span");
      p.className = "req__path";
      p.textContent = path;
      if (note) {
        const small = document.createElement("small");
        small.textContent = note;
        p.append(small);
      }
      el.append(v, p);
      if (kind !== "note") {
        const st = document.createElement("span");
        st.className = "req__status";
        st.textContent = status;
        el.append(st);
      }
      log.append(el);
      while (log.children.length > 9) log.firstElementChild.remove();
    }

    /* The browser's passkey sheet. Resolves true (used) or false (dismissed). */
    function prompt(auto) {
      sheet.hidden = false;
      return new Promise((resolve) => {
        answerSheet = (ok) => {
          answerSheet = null;
          sheet.hidden = true;
          resolve(ok);
        };
        if (auto) timers.push(setTimeout(() => answerSheet?.(true), reduced ? 0 : 1300));
        else $("sheet-ok").focus();
      });
    }

    async function request(verb, path, gated) {
      await sleep(260);
      if (gated && age > WINDOW) {
        line("reauth", verb, path, "403", "{ reauth: true }");
        return false;
      }
      line("ok", verb, path, "200");
      return true;
    }

    /* What a sensitive client call does: try, and on reauth confirm and retry once. */
    async function sensitive(verb, path, auto) {
      if (await request(verb, path, true)) return true;
      await sleep(200);
      line("ok", "POST", "/auth/reauth-options", "200");
      const used = await prompt(auto);
      if (!used) {
        line("note", "·", "Dismissed. authErrorMessage() returns null: nothing to show.");
        return false;
      }
      line("note", "✓", "Passkey used");
      await sleep(200);
      line("ok", "POST", "/auth/reauth-verify", "200");
      age = 0;
      renderFresh();
      return request(verb, path, true);
    }

    async function act(fn) {
      if (busy) return;
      busy = true;
      renderFresh();
      try {
        await fn();
      } finally {
        busy = false;
        renderFresh();
      }
    }

    const rename = () => act(() => request("PUT", "/auth/profile", false));
    const changeEmail = (auto) => act(() => sensitive("POST", "/auth/email-start", auto));
    const deleteAccount = (auto) =>
      act(async () => {
        if (!signedIn) {
          line("ok", "POST", "/auth/register-verify", "200", "new account");
          signedIn = true;
          age = 0;
          return;
        }
        if (await sensitive("POST", "/auth/delete-account", auto)) {
          signedIn = false;
          line("note", "·", "Account gone, cookie cleared.");
        }
      });
    const wait = () => {
      age += 6 * 60;
      line("note", "…", "Six minutes pass.");
      renderFresh();
    };

    function takeOver() {
      if (!scripted) return;
      scripted = false;
      timers.forEach(clearTimeout);
      timers = [];
      // Abandon the scripted call mid-flight: its pending steps never resume.
      answerSheet = null;
      sheet.hidden = true;
      busy = false;
    }

    $("act-rename").addEventListener("click", () => (takeOver(), rename()));
    $("act-email").addEventListener("click", () => (takeOver(), changeEmail(false)));
    $("act-delete").addEventListener("click", () => (takeOver(), deleteAccount(false)));
    $("act-wait").addEventListener("click", () => (takeOver(), wait()));
    $("sheet-ok").addEventListener("click", () => answerSheet?.(true));
    $("sheet-cancel").addEventListener("click", () => answerSheet?.(false));

    /* The thesis without a click: a fresh session changes the email freely,
       time passes, the same call is asked to confirm, confirms, and lands. */
    async function intro() {
      line("ok", "POST", "/auth/login-verify", "200", "signed in");
      await sleep(1100);
      if (!scripted) return;
      await rename();
      await sleep(1200);
      if (!scripted) return;
      wait();
      await sleep(1100);
      if (!scripted) return;
      await changeEmail(true);
      scripted = false;
    }

    renderFresh();
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          io.disconnect();
          void intro();
        }
      },
      { threshold: 0.25 },
    );
    io.observe(log);
  }

  /* ── recovery caps ───────────────────────────────────────────────── */

  const out = $("cap-out");
  if (out) {
    const PER_CODE = 5;
    const PER_DAY = 10;
    const PER_HOUR = 5;
    const SAME = "400 · That code is wrong or has expired";

    let code = null; // { attempts }
    let failures = 0;
    let sent = 0;

    function meter(id, n, max, label) {
      const el = $(id);
      el.querySelector(".meter__fill").style.width = `${Math.min(1, n / max) * 100}%`;
      el.dataset.full = String(n >= max);
      $(`${id}-n`).textContent = label ?? `${n} / ${max}`;
    }

    function render() {
      meter("m-code", code ? code.attempts : 0, PER_CODE, code ? `${code.attempts} / ${PER_CODE}` : "no code");
      meter("m-day", failures, PER_DAY);
      meter("m-hour", sent, PER_HOUR);
    }

    function say(text, tone) {
      out.textContent = text;
      out.dataset.tone = tone;
    }

    /* store.redeemCode, in the same order. */
    function redeem(right) {
      if (failures >= PER_DAY) return false;
      if (!code) return false;
      if (code.attempts >= PER_CODE) {
        code = null;
        return false;
      }
      if (!right) {
        failures++;
        code.attempts++;
        return false;
      }
      code = null;
      return true;
    }

    $("cap-send").addEventListener("click", () => {
      if (sent >= PER_HOUR) {
        say("200 · { ok: true }. Five codes already went to this email this hour, so nothing is sent. The answer doesn't say so.", "warn");
      } else {
        sent++;
        code = { attempts: 0 };
        say("200 · { ok: true }. A new six-digit code replaces any earlier one. It lasts 10 minutes.", "ok");
      }
      render();
    });

    $("cap-guess").addEventListener("click", () => {
      redeem(false);
      const locked = failures >= PER_DAY;
      say(
        locked
          ? `${SAME}. This email has 10 wrong guesses today: recovery for it is paused for a day.`
          : code
            ? `${SAME}.`
            : `${SAME}. That code is dead: send a new one (the daily count carries over).`,
        locked ? "bad" : "warn",
      );
      render();
    });

    $("cap-right").addEventListener("click", () => {
      if (redeem(true)) {
        say("200 · Signed in. Every other session signed out, every passkey revoked. Add a passkey for this device next.", "ok");
      } else {
        const why =
          failures >= PER_DAY
            ? "Even the right code: the email is locked for the day."
            : "No live code: none sent, or it died after 5 guesses.";
        say(`${SAME}. ${why}`, "bad");
      }
      render();
    });

    $("cap-reset").addEventListener("click", () => {
      code = null;
      failures = 0;
      sent = 0;
      say("A day later: the hourly and daily counts have aged out.", "ok");
      render();
    });

    render();
  }

  /* ── copy the install line ───────────────────────────────────────── */

  const copy = $("copy");
  copy?.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("install-cmd").textContent.trim());
      copy.dataset.copied = "true";
      copy.textContent = "Copied";
      setTimeout(() => {
        copy.dataset.copied = "false";
        copy.textContent = "Copy";
      }, 1600);
    } catch {
      /* Clipboard blocked — the text is right there to select. */
    }
  });
})();
