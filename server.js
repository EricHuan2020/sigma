import express from "express";
import * as cheerio from "cheerio";
import { randomUUID } from "node:crypto";
import fetchCookie from "fetch-cookie";
import { CookieJar } from "tough-cookie";

const app = express();
const PORT = process.env.PORT || 8080;
const ENTRY = "/go";
const SESSION_COOKIE = "relay_session";
const cookieJars = new Map();

app.use(express.static("public"));
app.use(ENTRY, express.raw({ type: "*/*", limit: "10mb" }));

const blocked = /^(localhost|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/;

const wrap = (base, link) => {
  try {
    if (/^(data:|javascript:|mailto:|#)/i.test(link)) return link;
    return `${ENTRY}?u=${encodeURIComponent(new URL(link, base).href)}`;
  } catch {
    return link;
  }
};

const rewriteCss = (css, base) =>
  css.replace(/url\(\s*['"]?([^'")]+)['"]?\s*\)/g, (_, u) => `url(${wrap(base, u)})`);

const requestBridge = (base) => `<script>(() => {
  const pageBase = new URL(${JSON.stringify(base).replace(/</g, "\\u003c")});
  const proxyPrefix = ${JSON.stringify(`${ENTRY}?u=`)};
  const rewrite = (input) => {
    const value = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    let url;
    try { url = new URL(value, pageBase); } catch { return input; }
    if (url.origin === location.origin) {
      if (url.pathname === ${JSON.stringify(ENTRY)} && url.searchParams.has("u")) return input;
      url = new URL(url.pathname + url.search + url.hash, pageBase);
    }
    return /^https?:$/.test(url.protocol) ? proxyPrefix + encodeURIComponent(url.href) : input;
  };
  const originalFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    const url = rewrite(input);
    if (url === input) return originalFetch(input, init);
    return originalFetch(input instanceof Request ? new Request(url, input) : url, init);
  };
  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    return originalOpen.call(this, method, rewrite(url), ...args);
  };
  if (navigator.sendBeacon) {
    const originalBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = (url, data) => originalBeacon(rewrite(url), data);
  }
  const originalPushState = history.pushState.bind(history);
  const originalReplaceState = history.replaceState.bind(history);
  history.pushState = (state, title, url) => originalPushState(state, title, url == null ? url : rewrite(url));
  history.replaceState = (state, title, url) => originalReplaceState(state, title, url == null ? url : rewrite(url));
  document.addEventListener("click", (event) => {
    const link = event.target.closest?.("a[href]");
    if (!link || event.defaultPrevented || event.button > 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    if (link.hasAttribute("download") || (link.target && link.target !== "_self")) return;
    const destination = rewrite(link.href);
    if (destination === link.href) return;
    event.preventDefault();
    window.location.assign(destination);
  }, true);
  const rewriteForm = (form, submitter) => {
    const action = rewrite(form.action);
    if (action !== form.action) form.action = action;
    if (submitter?.formAction) {
      const submitAction = rewrite(submitter.formAction);
      if (submitAction !== submitter.formAction) submitter.setAttribute("formaction", submitAction);
    }
  };
  document.addEventListener("submit", (event) => {
    if (event.target?.tagName === "FORM") rewriteForm(event.target, event.submitter);
  }, true);
  const originalSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function() {
    rewriteForm(this);
    return originalSubmit.call(this);
  };
})();</script>`;

const getCookieJar = (req, res) => {
  const match = (req.get("cookie") || "").match(/(?:^|;\s*)relay_session=([0-9a-f-]{36})(?:;|$)/i);
  const sessionId = match?.[1] || randomUUID();
  let jar = cookieJars.get(sessionId);
  if (!jar) {
    jar = new CookieJar();
    if (cookieJars.size >= 1000) cookieJars.delete(cookieJars.keys().next().value);
    cookieJars.set(sessionId, jar);
  } else {
    cookieJars.delete(sessionId);
    cookieJars.set(sessionId, jar);
  }
  res.cookie(SESSION_COOKIE, sessionId, { httpOnly: true, sameSite: "lax", path: "/" });
  return jar;
};

app.all(ENTRY, async (req, res) => {
  let target;
  try {
    target = new URL(String(req.query.u || ""));
  } catch {
    return res.status(400).send("Invalid address");
  }
  for (const [key, value] of Object.entries(req.query)) {
    if (key === "u") continue;
    for (const item of Array.isArray(value) ? value : [value]) {
      target.searchParams.append(key, String(item));
    }
  }
  if (!/^https?:$/.test(target.protocol) || blocked.test(target.hostname)) {
    return res.status(400).send("Address not allowed");
  }

  try {
    const headers = new Headers();
    const excludedHeaders = new Set([
      "accept-encoding", "connection", "content-length", "cookie", "host", "keep-alive",
      "origin", "referer", "te", "trailer", "transfer-encoding", "upgrade",
    ]);
    for (const [name, value] of Object.entries(req.headers)) {
      if (!excludedHeaders.has(name) && !name.startsWith("sec-") && value) {
        headers.set(name, Array.isArray(value) ? value.join(", ") : value);
      }
    }
    headers.set("user-agent", req.get("user-agent") || "Mozilla/5.0");
    headers.set("accept", req.get("accept") || "*/*");
    headers.set("accept-language", req.get("accept-language") || "en-US,en;q=0.9");
    const incomingReferer = req.get("referer");
    let referer = incomingReferer;
    try {
      const parsedReferer = new URL(incomingReferer);
      if (parsedReferer.hostname === req.hostname) {
        referer = parsedReferer.searchParams.get("u") || undefined;
      }
    } catch {}
    if (referer) headers.set("referer", referer);
    if (req.get("origin")) {
      headers.set("origin", referer ? new URL(referer).origin : target.origin);
    }
    const cookieJar = getCookieJar(req, res);
    const upstream = await fetchCookie(fetch, cookieJar)(target, {
      redirect: "follow",
      headers,
      method: req.method,
      ...(!["GET", "HEAD"].includes(req.method) && req.body?.length ? { body: req.body } : {}),
    });

    const base = upstream.url;
    const type = upstream.headers.get("content-type") || "";
    res.status(upstream.status).set("content-type", type);

    if (type.includes("text/html")) {
      cookieJar.lastPage = base;
      const $ = cheerio.load(await upstream.text());
      const map = {
        a: "href", link: "href", script: "src", img: "src",
        source: "src", iframe: "src", video: "src", audio: "src",
      };
      for (const [tag, attr] of Object.entries(map)) {
        $(tag).each((_, el) => {
          const v = $(el).attr(attr);
          if (v) $(el).attr(attr, wrap(base, v));
        });
      }
      $("form[action], button[formaction], input[formaction]").each((_, el) => {
        const attr = $(el).is("form") ? "action" : "formaction";
        $(el).attr(attr, wrap(base, $(el).attr(attr)));
      });
      $("img[srcset], source[srcset]").removeAttr("srcset");
      $("meta[http-equiv='Content-Security-Policy']").remove();
      $("head").prepend(requestBridge(base));
      $("style").each((_, el) => $(el).text(rewriteCss($(el).text(), base)));
      return res.send($.html());
    }

    if (type.includes("text/css")) {
      return res.send(rewriteCss(await upstream.text(), base));
    }

    res.send(Buffer.from(await upstream.arrayBuffer()));
  } catch (err) {
    res.status(502).send("Could not reach that site: " + err.message);
  }
});

app.all(/^\/(?!go(?:\/|$)).+/, (req, res, next) => {
  const match = (req.get("cookie") || "").match(/(?:^|;\s*)relay_session=([0-9a-f-]{36})(?:;|$)/i);
  const cookieJar = match && cookieJars.get(match[1]);
  let base = cookieJar?.lastPage;
  try {
    const referer = new URL(req.get("referer"));
    if (referer.hostname === req.hostname && referer.pathname === ENTRY) {
      base = referer.searchParams.get("u") || base;
    }
  } catch {}
  if (!base) return next();
  try {
    const target = new URL(req.originalUrl, base);
    return res.redirect(307, `${ENTRY}?u=${encodeURIComponent(target.href)}`);
  } catch {
    return next();
  }
});

app.listen(PORT, () => console.log(`Running on port ${PORT}`));
