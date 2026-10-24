# Security

## Threat model (single operator, own Mac)

Platform: Apple Silicon macOS 14+ (including macOS 27, which is Apple silicon only) is the target and the only supported install; Intel is best-effort on macOS 26 or older. Linux is best-effort for development and CI.

Assets: corpus, mail/calendar data, OAuth refresh token, API keys, the ability to send mail or SMS.
Adversaries: (1) content authors, meaning anyone who can put text in front of the model (web pages,
emails, calendar invites, attachments, Telegram/SMS senders); (2) other local users; (3) network
observers. Out of scope: an attacker already running code as your user.

## Rule of Two

A turn may combine at most two of: untrusted input, access to private data, and the ability to act
externally. cg-researcher enforces this in the graph, not in the prompt:

- Untrusted input (attachments, web/mail/calendar output) taints the turn, and a tainted turn
  never auto-approves a write.
- Retrieved corpus blocks also taint the turn whenever included in the local model prompt,
  independently of injection-pattern matches. Automatic writes apply only to CLI turns;
  HTTP always consults its denying confirmer, even if auto-approval is configured.
- Remote origins (Telegram/SMS) get read-only tools and cannot approve writes. SMS can never
  approve the external model.
- Writes (`gmail_send`, `gmail_create_draft`, `gcal_create_event`) always need a human "yes"
  that shows the full recipient, subject and body. The HTTP API cannot give that yes.
- Model output is filtered: markdown images are removed and links with query strings are cut
  to their host, which closes the classic exfiltration channel.

## Known weaknesses (accepted, documented)

- **macOS Keychain write:** `security add-generic-password -w <value>` puts the refresh token on
  argv for the call's lifetime, so a same-user `ps` can read it. This is accepted under the
  single-operator model. The file fallback is 0600.
- **Audit tail truncation:** a signed head (`audit.pb.head`: count + last MAC, HMAC'd under a
  separate label) now catches removal of whole trailing records. Limit: a same-user attacker who can
  read `audit.key` can forge a head for a truncated log. Detecting that needs an off-host anchor (copy
  `audit tail -n 1` elsewhere).
- **Rename leftovers:** Keychain items under the old `cg-agent` service are not migrated (that would
  mean reading secrets in a script); `uninstall.sh --purge` deletes them.
- **Keychain prompts after rebuilds:** binaries are ad-hoc signed, not Developer-ID signed, so each
  rebuild changes the code identity. macOS then shows an "Always Allow" prompt once per Keychain item.
  There is no notarization.
- **External providers:** whatever you allow in `[external.rules]` leaves the machine. Anthropic's
  and xAI's retention policies apply. The call budget lives in memory and resets when the process
  restarts. xAI chat-completions retention was not independently verified.
- **Web UI sessions** are in memory (lost on restart), and anyone with the API key can mint a pairing
  code. The UI is a same-user tool, not a multi-user one.
- **SMS:** caller ID is spoofable, so the PIN is the real gate. Twilio retains messages; cg-researcher
  deletes processed inbound messages, but outbound replies stay in Twilio's log.
- **Telegram:** Bot API traffic is not end-to-end encrypted; Telegram can read it.
- **Public Google fallback:** fragile, ToS-grey, and off by default.
- **Pattern-based injection filtering** is a speed bump, not a boundary. The boundaries are the
  tool gate, taint, and origin rules above.
- `/health` is unauthenticated and reveals only `{ok, local_model}`.

## Supply chain

- The workspace forbids `unsafe` (`unsafe_code = "forbid"`); the only C is SQLite itself
  (rusqlite `bundled`, with FTS5). No SQLite extensions are loaded.
- sqlite-vec was evaluated and rejected: pre-1.0 C (~10k lines), a past heap overflow
  (CVE-2024-46488, npy parsing, fixed in 0.1.3), a null `pzErrMsg` write in `sqlite3_vec_init`, and
  brute-force KNN that gives no speed advantage over the in-RAM Rust scan at this scale.
- Release artifacts: ad-hoc signed, SHA-256 published, draft-only, build provenance attested when the
  repository is public.

## Web UI threat model

Assumed attacker: a malicious web page in the same browser. Mitigations:
- Host-header allowlist (DNS rebinding returns 421), and an `Origin` check that refuses cross-origin
  requests with 403. There is no CORS.
- Auth is a bearer token sent in a header. Cookies are never used, so CSRF has nothing to ride on.
- The pairing code travels in the URL fragment, is single-use, expires after 120 s, and is
  scrubbed from history.
- CSP `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self';
  frame-ancestors 'none'`, plus nosniff, no-referrer, no-store, COOP/CORP and a Permissions-Policy.
  All model or server text is rendered with `textContent`; a test fails the build on any
  HTML-string sink.
- Streamed answers (`/query/stream`) pass the same output guard as final answers before they leave
  the process. The guard re-runs over the whole buffered answer, stops streaming if guarding would
  change text already sent, and holds back the tail that could still be the start of a secret.
- A settings whitelist plus 409-unless-acknowledged for any relaxation. The UI can never grant write
  approval, change the bind address or enable connectors.

## Reporting

Open a private security advisory on the GitHub repository.
