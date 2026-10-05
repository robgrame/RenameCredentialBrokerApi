# Architecture overview email template

`DeviceCredentialBroker-Architecture-Email.eml` is a ready-to-send email
(standard RFC 822 `.eml`, HTML body) explaining the Device Credential Broker
architecture, with emphasis on the device authentication/authorization
pipeline. `From`/`To`/`Subject` are placeholders to be replaced before
sending.

## Why double-clicking it looks "read-only"

Double-clicking an `.eml` opens it as a **preview of a received message**,
so most clients lock `From`/`To`/`Subject` and the body. This is expected
`.eml` behavior, not a problem with the file — the fix is to bring it into
your mail client as a **draft** rather than previewing it.

## How to make it editable

**Outlook (classic/desktop) — recommended, most reliable:**
1. Open Outlook and go to your **Drafts** folder.
2. In File Explorer, **drag and drop** `DeviceCredentialBroker-Architecture-Email.eml`
   directly onto the Drafts folder (or onto the message list while Drafts is
   open).
3. Outlook imports it as a real draft: double-click it from Drafts and
   `From` (sending account), `To`, `Subject`, and the body are now fully
   editable, exactly like any email you started yourself.
4. Edit the placeholders, then send.

**Outlook (classic/desktop) — alternative, no drag-and-drop needed:**
1. Double-click the `.eml` to open it as a preview.
2. On the ribbon: **Message → Actions → Edit Message** (older versions:
   **Other Actions → Edit Message**).
3. This unlocks the recipient fields and body for direct editing.

**New Outlook / OWA (no "Edit Message" option exposed):**
1. Drag the `.eml` into the Drafts folder the same way as above — this is
   the only reliable method, since new Outlook does not expose "Edit
   Message" for previewed `.eml` files.

**Thunderbird:**
1. Drag the `.eml` into any folder in your mailbox, then right-click the
   imported message → **Edit as New Message**.
