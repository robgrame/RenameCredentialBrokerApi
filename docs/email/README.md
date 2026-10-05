# Architecture overview email template

`DeviceCredentialBroker-Architecture-Email.eml` is a ready-to-send email
(standard RFC 822 `.eml`, HTML body) explaining the Device Credential Broker
architecture, with emphasis on the device authentication/authorization
pipeline. `From`/`To`/`Subject` are placeholders to be replaced before
sending.

## It opens directly as an editable draft

The file includes the `X-Unsent: 1` header, which both classic Outlook and
current "New Outlook" builds (Windows) recognize as "this is an unsent
draft, not a received message" — so double-clicking it opens it **already
editable**: `From` (sending account), `To`, `Subject`, and the body can all
be changed, and the **Send** button is active immediately.

1. Double-click `DeviceCredentialBroker-Architecture-Email.eml`.
2. It opens in Outlook as a draft (not a read-only preview).
3. Replace the `To` address, pick your sending account, adjust the subject
   if needed, edit the signature placeholders in the body.
4. Click **Send**.

## If it still opens read-only

`X-Unsent: 1` requires a reasonably current Outlook + WebView2 build. If
your Outlook is on an older build, or another client ignores the header:

**Outlook (classic/desktop) — fallback:**
1. Open Outlook's **Drafts** folder.
2. Drag and drop the `.eml` file from File Explorer onto the Drafts folder.
3. Outlook imports it as a genuine draft: open it from Drafts and every
   field is editable.

**Outlook (classic/desktop) — alternative:**
1. Double-click the `.eml` to open it as a preview.
2. On the ribbon: **Message → Actions → Edit Message** (older versions:
   **Other Actions → Edit Message**).

**Thunderbird:**
1. Drag the `.eml` into any folder in your mailbox, then right-click the
   imported message → **Edit as New Message**.
