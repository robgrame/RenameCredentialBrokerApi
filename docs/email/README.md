# Architecture overview email template

This folder contains a ready-to-send email explaining the Device Credential
Broker architecture, with emphasis on the device authentication/authorization
pipeline.

## Why two files?

- **`DeviceCredentialBroker-Architecture-Email.eml`** — a full `.eml` message
  (headers + HTML body). Most mail clients (Outlook included) open a
  double-clicked `.eml` as if it were an **already-sent/received message**,
  so the `From`, `To`, and sometimes the body are shown **read-only** and
  cannot be edited in place.
- **`DeviceCredentialBroker-Architecture-Email-Body.html`** — the same
  content as a **standalone HTML file**, with no email headers. Use this one
  if your mail client won't let you edit the `.eml` directly.

## How to use it (editable)

**Option A — fix the `.eml` in Outlook (classic/desktop Outlook):**
1. Double-click the `.eml` to open it.
2. Go to the message ribbon → **Actions** → **Edit Message** (or **Other
   Actions → Edit Message** depending on version). This unlocks `To`,
   `From`/account selection, `Subject`, and the body for editing.
3. Edit the recipient, pick your sending account, adjust the subject, and
   send.

**Option B — copy/paste the HTML body into a brand-new email (works in any
client, including new Outlook / OWA, which do not expose "Edit Message"):**
1. Open `DeviceCredentialBroker-Architecture-Email-Body.html` in a web
   browser (double-click it).
2. Select all the rendered content (`Ctrl+A`) and copy it (`Ctrl+C`).
3. In your mail client, start a **new email** (so `To`/`From`/`Subject` are
   natively editable from the start).
4. Paste (`Ctrl+V`) into the email body — formatting is preserved because
   it's HTML, not plain text.
5. Fill in `To`, `Subject`, and your signature placeholder, then send.

Option B is the most reliable across clients, since it never depends on an
"edit a received message" feature that not every client exposes.
