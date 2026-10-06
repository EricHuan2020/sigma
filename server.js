import express from "express";
import * as cheerio from "cheerio";

const app = express();
const PORT = process.env.PORT || 8080;
const ENTRY = "/go";

app.use(express.static("public"));

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

app.get(ENTRY, async (req, res) => {
  let target;
  try {
    target = new URL(String(req.query.u || ""));
  } catch {
    return res.status(400).send("Invalid address");
  }
  if (!/^https?:$/.test(target.protocol) || blocked.test(target.hostname)) {
    return res.status(400).send("Address not allowed");
  }

  try {
    const upstream = await fetch(target, {
      redirect: "follow",
      headers: {
        "user-agent": req.get("user-agent") || "Mozilla/5.0",
        accept: req.get("accept") || "*/*",
        "accept-language": req.get("accept-language") || "en-US,en;q=0.9",
      },
    });

    const base = upstream.url;
    const type = upstream.headers.get("content-type") || "";
    res.status(upstream.status).set("content-type", type);

    if (type.includes("text/html")) {
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
      $("img[srcset], source[srcset]").removeAttr("srcset");
      $("meta[http-equiv='Content-Security-Policy']").remove();
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

app.listen(PORT, () => console.log(`Running on port ${PORT}`));
