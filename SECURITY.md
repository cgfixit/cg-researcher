# Security

## Threat model (single operator, own machine)

Assets: corpus, mail/calendar data, OAuth refresh token, API keys, the ability to send mail or SMS.
Adversaries: (1) content authors, meaning anyone who can put text in front of the model (web pages,
emails, calendar invites, attachments, Telegram/SMS senders); (2) other local users; (3) network
observers. Out of scope: an attacker already running code as your user.

## Rule of Two

A turn may combine at most two of: untrusted input, access to private data, and the ability to act
externally. cg-agent enforces this in the graph, not in the prompt:

- Untrusted input (attachments, web/mail/calendar output) taints the turn, and a tainted turn
  never auto-approves a write.
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
- **Audit tail truncation:** the HMAC chain detects edits, reordering and partial frames, but not
  the removal of whole trailing records. Anchor it externally (for example, copy `audit tail -n 1`
  elsewhere) if that matters to you.
- **SMS:** caller ID is spoofable, so the PIN is the real gate. Twilio retains messages; cg-agent
  deletes processed inbound messages, but outbound replies stay in Twilio's log.
- **Telegram:** Bot API traffic is not end-to-end encrypted; Telegram can read it.
- **Public Google fallback:** fragile, ToS-grey, and off by default.
- **Pattern-based injection filtering** is a speed bump, not a boundary. The boundaries are the
  tool gate, taint, and origin rules above.
- `/health` is unauthenticated and reveals only `{ok, local_model}`.

## Reporting

Open a private security advisory on the GitHub repository.
