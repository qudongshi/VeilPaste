# VeilPaste Static Site

This folder contains the static pages needed for the Chrome Web Store listing:

- `index.html`: product overview
- `privacy.html`: public privacy policy URL
- `support.html`: support and contact page
- `site-i18n.js`: browser-language switching for the three pages

The public support email is `qudongshi@gmail.com`.

## Language Behavior

The pages use the browser's preferred language:

- `zh*`: Chinese
- everything else: English

The HTML defaults to Chinese when JavaScript is unavailable. When JavaScript is
available, `site-i18n.js` also updates `<html lang>`, `<title>`, and the meta
description.

## Local Preview

Open `index.html` directly in a browser, or run a simple static server from this
folder:

```bash
python3 -m http.server 8080
```

Then open:

```txt
http://localhost:8080/
```

## Pre-Deploy Check

From the repository root:

```bash
node --check site/site-i18n.js
python3 -m http.server 8080 --directory site
```

Then confirm these pages load:

```txt
http://localhost:8080/
http://localhost:8080/privacy.html
http://localhost:8080/support.html
```

In a browser with a non-`zh*` preferred language, confirm the visible page text
switches to English.

## GitHub Pages

The repository includes `.github/workflows/pages.yml`, which publishes this
folder with GitHub Pages Actions after changes to `site/` are pushed to `main`.

In GitHub repository settings, set Pages source to GitHub Actions.

Expected project Pages URLs:

```txt
https://qudongshi.github.io/VeilPaste/
https://qudongshi.github.io/VeilPaste/privacy.html
https://qudongshi.github.io/VeilPaste/support.html
```
