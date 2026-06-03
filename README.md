# Soyjak.st Poster Tools & Userscripts

A collection of power-user tools and userscripts for interacting with the imageboard `soyjak.st`. This repository includes an automated Python posting client and several Tampermonkey/Violentmonkey browser userscripts designed to anonymize files, spoof browser fingerprints/integrity checks, and protect deleted posts in the DOM.

> **Note:** This project is a bit old, but it is well-designed and should still work with proper environment configuration.

---

## Table of Contents

- [Overview of Included Files](#overview-of-included-files)
- [Python Posting Client: `poster.py`](#python-posting-client-posterpy)
  - [Key Features](#key-features)
  - [Prerequisites & Installation](#prerequisites--installation)
  - [CLI Usage & Examples](#cli-usage--examples)
  - [Important Limitations](#important-limitations)
- [Browser Userscripts](#browser-userscripts)
  - [1. Fingerprint Spoofer (`sharty_fingerprint_spoofer.user.js`)](#1-fingerprint-spoofer-sharty_fingerprint_spooferuserjs)
  - [2. File Anonymizer (`sharty_file_anonymizer.user.js`)](#2-file-anonymizer-sharty_file_anonymizeruserjs)
  - [3. Prevent Post Deletion (`sharty_prevent_post_deletion.user.js`)](#3-prevent-post-deletion-sharty_prevent_post_deletionuserjs)
- [Anti-Bot Filters & Troubleshooting Errors](#anti-bot-filters--troubleshooting-errors)

---

## Overview of Included Files

1. **`poster.py`**: A robust command-line client to submit threads and replies to `soyjak.st` while emulating valid browser TLS configurations and encrypting the required anti-fingerprint integrity challenge.
2. **`sharty_fingerprint_spoofer.user.js`**: A browser userscript that intercepts WebAssembly (WASM) instantiation, hooks Emscripten's `ccall`, and spoofs the client integrity response directly in the browser.
3. **`sharty_file_anonymizer.user.js`**: An upload companion userscript that sanitizes metadata, randomizes filenames, and alters files at the byte/pixel level before submission to bypass image-level deduplication and automatic bans.
4. **`sharty_prevent_post_deletion.user.js`**: An anti-deletion script that intercepts the AJAX thread updates, identifies posts deleted by janitors, and prevents jQuery from removing them from your DOM (marking them visually as `[Deleted]` instead).

---

## Python Posting Client: `poster.py`

`poster.py` mimics a real browser session to submit posts without leaking your machine's true automated signature.

### Key Features
- **TLS & Fingerprint Emulation**: Uses custom configurations from a `fingerprints` library (Chrome, Firefox, Safari) combined with `curl_cffi` to bypass Akamai and Cloudflare client signature matching.
- **Integrity Payload Generation**: Intercepts anti-bot tracking data and computes the necessary encrypted AES-CBC challenge payload using a static key:
  `2F 20 43 6A C0 52 69 21 1A 50 DD E4 2E D5 B4 A1`.
- **Filename & Hash Randomization**: Automatically modifies files (changing pixel values or trailing bytes depending on format) and shifts filenames to a Unix epoch timestamps format, throwing off server-side deduplication.
- **Comment Bypass Filters**: Offers an option to insert zero-width whitespace characters inside comment words (`--bypass-banned-text`) to dodge regex-based comment/word bans.
- **Session Caching**: Reuses a pool of browser fingerprints cached by IP address (default size of 4 stored in `poster.cache`) to prevent fingerprint mismatches across multiple calls from the same IP.

### Prerequisites & Installation

Ensure you have Python 3.8+ installed. Install the required external libraries:

```bash
pip install curl_cffi pycryptodome Pillow
```

*Note on custom libraries:* This script references supplementary custom libraries from directory paths (e.g., `../libs/fingerprints.py`). Maintain the original folder structure when checking out or copying this file.

*Critical curl_cffi Bug Warning:*
In some releases of `curl_cffi`, custom fingerprints may get overwritten by default configurations. It is highly recommended to apply this patch to fix `extra_fp` being overwritten:
[curl_cffi Pull Request #680](https://github.com/lexiforest/curl_cffi/pull/680).

### CLI Usage & Examples

To see all available configuration flags:
```bash
python poster.py --help
```

#### 1. Post a Text Comment in a Thread (using a proxy)
```bash
python poster.py "https://soyjak.st/soy/thread/12345.html" --comment "Hello from CLI" --proxy "socks5h://127.0.0.1:1080"
```

#### 2. Create a New Thread with an Image (and bypass word filters)
```bash
python poster.py "https://soyjak.st/qa/" --subject "New Thread" --comment "Look at this image" --file "path/to/my_image.png" --bypass-banned-text
```

#### 3. Upload Multiple Files without Randomizing Filenames
```bash
python poster.py "https://soyjak.st/pol/thread/98765.html" --file "pic1.jpg" --file2 "pic2.png" --no-random-filename
```

### Important Limitations
- ❌ **No Auto-Captcha Solving**: `poster.py` **does not** automatically solve captchas. If the board demands a captcha verification block to submit the post, the script will fail or expect the captcha logic to be bypassed/disabled.
- ⚠️ **False-Positive Terminal Warnings**: You may occasionally encounter an `"integrity check failed"` error printed in the terminal, but the post itself will still successfully publish. Always verify the board page first to check if the reply landed.

---

## Browser Userscripts

Install a userscript manager like [Violentmonkey](https://violentmonkey.github.io/) or [Tampermonkey](https://www.tampermonkey.net/) in your browser to run these scripts.

### 1. Fingerprint Spoofer (`sharty_fingerprint_spoofer.user.js`)

Blocks client-side fingerprinters and overrides the WebAssembly-based fingerprint payload computation dynamically during browser interaction.

- **How it works**:
  - Hijacks `WebAssembly.instantiate` and `WebAssembly.instantiateStreaming` to hook imported functions.
  - Monkey-patches Emscripten's `ccall` (`Module.ccall`) to intercept calls computing the integrity hash.
  - Automatically clears site cookies and resets user post passwords after posting to generate fresh and completely distinct sessions, preventing account/post tracking.
- **Requirements**: Needs access to `api.ip2location.io` or `soyjak.st/inc/ip.php` to fetch geolocation timezone data for fingerprint alignment.
- **Settings**: Adjust top-level variables (`REFETCH_IP_ON_EACH_CALL`, `REUSE_FINGERPRINT`, `RESET_COOKIES_AND_PASSWORD`) inside the script source to fine-tune automation properties.
- **⚠️ Janny Detection Disclaimer**: Automated userscripts can be programmatically detected by administrators/janitors through standard behavior tests. If you suspect detection or bans:
  1. Pass the userscript code through a **JavaScript minifier** to obscure script logic and randomize variable/function names.
  2. Toggle `STRINGIFY_LOGS = false` or remove `console.log` instructions entirely to avoid leaking execution trace logs in the browser console.
  3. Understand that this script **does not** prevent transport-layer identifiers such as Browser User-Agent string discrepancy or TCP/TLS fingerprints (JA3/JA4) evaluated by reverse proxies like Cloudflare.

---

### 2. File Anonymizer (`sharty_file_anonymizer.user.js`)

A must-have for uploading media. Strips file EXIF profiles and modifies raw image structure on-the-fly to secure unique hash fingerprints for every upload.

- **How it works**:
  - Intercepts file drop actions, copy-pastes, and standard file selection fields.
  - **JPEG/PNG**: De-serializes and re-encodes images directly in your browser. It changes a single random color channel (R, G, or B) of a random non-transparent pixel within the first 25% of the image by a subtle, imperceptible shift of `50` to `127` units.
  - **GIF/WebM**: Performs byte-level noise injection near the file terminator block (2 to 8 bytes offset) to shift cryptographic signatures without corrupting animations.
- **Settings**:
  - `USE_CANVAS`: Set to `false` (default) to utilize client-side pure JS encoders (`upng-js`, `jpeg-js` loaded automatically through CDNs via `@require`). Setting to `true` relies on HTML5 Canvas APIs, which requires permission and may trigger browser anti-fingerprinting canvas warning blocks.
  - `FAKE_FILENAME`: Overwrites filenames with fake epoch-timestamped names to prevent leakage of local structures.

---

### 3. Prevent Post Deletion (`sharty_prevent_post_deletion.user.js`)

Preserves deleted responses inside your thread views. It prevents threads from shrinking dynamically when content gets deleted by moderators.

- **How it works**:
  - Intercepts jQuery's global AJAX update handler used by the site's automated auto-updater.
  - Tracks incoming replies and uses custom algorithms (*Annihilation*, *Contraction*, *Order*, and *Gap* heuristics) to identify missing posts.
  - Temporarily overrides jQuery's `.remove()` API block. When the site tries to delete the element, the script catches it, shields the HTML reply node and its associated layout breaks (`<br.clear>`), and appends a red `<span class="deleted-notice">[Deleted]</span>` label.
- **⚠️ Important Limitation**:
  - **Does not work well on partial loaded threads** opened via the **"Last 50 Posts"** page links. The layout and truncated elements on partial views disrupt the script’s stateful heuristics, preventing accurate deletion tracking.

---

## Anti-Bot Filters & Troubleshooting Errors

If you encounter persistent posting failures, take note of these custom security configurations deployed on the board:

1. **"Something went wrong. Please try again later." (Anti-New IP Filter)**
   - Jannies occasionally toggle an aggressive gatekeeping filter that blocks *all postings from newly seen or fresh IP addresses*. If this filter is active, your browser or `poster.py` client will be rejected with this error until the address gathers natural traffic history or the filter is relaxed.
2. **Anti-VPN Filter (Same Error Message)**
   - When the same "Something went wrong" message appears on commercial network blocks, it is typically due to the anti-VPN IP blocklist filter. Switch to high-quality residential proxies, standard home ISPs, or mobile connections to bypass.
3. **WASM & Javascript Challenges**
   - The spoofer and python scripts work hard to handle standard integrity challenge equations. If a full Captcha block is triggered (such as Cloudflare Turnstile or board-specific graphic tests), you must solve them manually in your browser; automation under `poster.py` will not proceed through captchas.
4. **Manual "Ban Evasion" Bans**
   - Sometimes you may get banned for "ban evasion" even for completely benign posts. This is **not due to any script failure or fingerprint leak**. Instead, it occurs because janitors obsessively check the post history of active IP addresses, manually flagging and banning fresh/zero-post-history IPs that submit posts matching the typical stylistic traits or images of known ban-evader.
