# noncey — Provider Configuration: Concept Reference

This document defines the conceptual model of **Provider Configurations** in noncey.
It is the authoritative reference for terminology, lifecycle, data model intent, and
all flows that relate to configurations. Implementation details live in `ARCHITECTURE.md`;
this document defines the *what* and *why*.

---

## 1. Terminology

| Term | Long form | Meaning |
|---|---|---|
| **Provider Configuration** | — | The top-level named bundle; the core unit of the system |
| **Channel** | provider's OTP transmission channel | One OTP delivery path (an email source + extraction rule) |
| **Header** | channel header | A routing rule that matches an incoming email to a Channel |
| **Prompt** | — | The browser-side fill instruction: `{url, selector}` |

> **Note on "Header":** The term is deliberately semantic rather than technical.
> Internally, Headers are matched against email envelope fields (sender address,
> subject). The name reflects *what the email says about itself*, not how it is implemented.

---

## 2. What a Provider Configuration Is

A Provider Configuration is a **named bundle** that ties together everything needed
for end-to-end OTP relay for one service:

```
Provider Configuration
  ├── name            (user-chosen; unique in the public namespace per version)
  ├── 1–n  Channels   (each: extraction source, mode, markers/length)
  │         └── 1–n  Headers  (each: sender email match / subject regex)
  └── 1    Prompt     ({url, selector} — the OTP field on the target web page)
```

A configuration is only **functional** when all three elements are present.
The Prompt is authored in the Chrome extension via the visual field picker and
stored at the daemon — it is not a client-local artefact.

---

## 3. State Model

Every Provider Configuration carries two independent dimensions:

### 3a. Status

| Status | Meaning |
|---|---|
| `incomplete` | Missing ≥1 required element (Channel+Header or Prompt) |
| `valid` | All elements present; ready to activate |
| `valid+tested` | Valid, and successfully tested end-to-end ≥3 times |

### 3b. Visibility

| Visibility | Meaning |
|---|---|
| `private` | Owned and editable by one user; not visible to others |
| `public` | Published to the marketplace; read-only; any user may subscribe |

**Initial state on creation:** `status=incomplete, visibility=private`.

---

## 4. Status Transitions

```
                  ┌─────────────────────────────────────────────────────┐
                  │  Remove Channel+Header OR Prompt                     │
                  ▼                                                       │
            [incomplete]  ───── all elements present ──────▶  [valid]   │
                  │                                              │   ▲   │
           (auto-delete                                          │   │   │
            if no content                                  3 client  │   │
            remains at all)                                tests  any│   │
                                                             │   change  │
                                                             ▼   (excl. │
                                                        [valid+tested]  │
                                                             │          │
                                                         submit for     │
                                                         publication    │
                                                             │
                                                             ▼
                                                      admin approves
                                                             │
                                                             ▼
                                                  visibility → public
                                                  status → valid
                                                  (read-only henceforth)
```

### Completeness rule

A configuration transitions **automatically** between `incomplete` and `valid`
as elements are added or removed:

- Becomes `valid` when: ≥1 Channel with ≥1 Header, AND 1 Prompt are all present
- Becomes `incomplete` when: any Channel (with its Headers) is removed, or the Prompt is removed
- Loses `valid+tested` when: any structural change is made (except renaming), or status drops to `incomplete`

### Auto-deletion rule

A configuration with **no Channels and no Prompt** is deleted automatically.
This prevents ghost entries when a user abandons setup partway through.

---

## 5. Versioning

Versions are **only meaningful for public configurations**.

- Private configurations carry version `-1` internally; this is never displayed to the user.
- At the moment of publication (admin approval), the daemon assigns a version automatically:
  `YYYYMM-NN`, where `YYYYMM` is the publication month and `NN` starts at `01`,
  incrementing if that slot is already taken (`02`, `03`, …).
- The public namespace uniqueness key is `(name, version)`.
- Multiple users may publish configurations with the same name; each receives its own version.
- Subscribers to an older version are shown a notification and an **Update** button
  when a newer version of the same name is published by any user.

### Versioning example

```
April 2026:
  User A publishes "eBay"  →  version 202604-01
  User B publishes "eBay"  →  version 202604-02  (slot -01 taken)

User A, who was subscribed to 202604-01, sees:
  "eBay 202604-01  [Update available: 202604-02]"
```

---

## 6. Roles

| Actor | Where | Capabilities |
|---|---|---|
| **User (owner)** | Server UI + Chrome extension | Create / edit private configs; activate / deactivate; submit for publication |
| **Admin** | Server UI | All of the above + approve / reject submissions; delete public configs; see subscriber counts (with names if < 3 subscribers) |
| **Subscriber** | Server UI + Chrome extension | Subscribe / unsubscribe to public configs; fork a public config to a new private one |
| **Chrome extension** | REST API | Read own configs + subscriptions; push Prompt; report test count; poll nonces |
| **ingest.py** | Postfix pipe | Route emails; create nonces for channels of active / subscribed configurations |

> **Testing is client-side only.** The Chrome extension counts successful end-to-end
> fills (nonce received → correct field filled). The daemon's `test_count` column
> is obsolete and will be removed. `ingest.py` does not increment any counter.

---

## 7. Activation and Subscription (equivalent operations)

Activation (for private configs) and subscription (for public configs) are the
**same logical operation**: they signal that the daemon should route matching emails
for this user according to this configuration, and that the Chrome extension should
poll and act on resulting nonces.

| Operation | Target | Effect |
|---|---|---|
| **Activate** | private `valid` config | Daemon routes matching emails; client polls nonces |
| **Deactivate** | private `valid` config | Daemon stops routing; client stops polling |
| **Subscribe** | public `valid` config | Same as activate — creates user↔config relationship; always active on creation |
| **Unsubscribe** | subscribed public config | Removes user↔config relationship |

Subscribing does **not clone** the configuration. It creates an entry in the
`subscriptions` join table (`user_id`, `config_id`). The daemon consults this table
to know which configurations to apply when routing email for a given user.

**Forking** — creating an editable private copy from a public configuration — is a
separate, distinct operation. It creates a new `private` configuration owned by the
user, copying Channels, Headers, and Prompt. The fork starts at `status=valid` if
all elements are present, or `status=incomplete` otherwise.

---

## 8. Lifecycle Flows

### 8a. Creation flow

Creation spans two surfaces: the Server UI and the Chrome extension.

```
1. Server UI
   User creates a new Provider Configuration (name only).
   → status=incomplete, visibility=private, version=-1 (not displayed)

2. Server UI
   User adds ≥1 Channel and ≥1 Header.
   Typically guided by an unmatched email already in the inbox.

3. Chrome extension
   User navigates to the target OTP page.
   User activates the visual field picker.
   User clicks the OTP input field.
   → extension captures {url, selector} and pushes to daemon as the Prompt.

4. (automatic)
   Configuration transitions to status=valid.

5. Server UI or Chrome extension
   User activates the configuration.
   → daemon begins routing; client begins polling.
```

### 8b. Publication flow

```
incomplete  ──(all elements present)──────────────────────> valid
                                                               |
                                             client_test_count >= 3
                                             (reported by extension)
                                                               |
                                                               v
public <──(admin approve)── pending_review <──(submit)── valid_tested
  |                                ^
  |                         (admin reject)
  └────────────────────────────────┘  (back to valid_tested; owner revises and resubmits)
```

```
Precondition: private configuration at status=valid+tested

1. Owner submits for review (Server UI).
   Pre-check: if a public configuration with this name already exists → auto-reject.

2. Admin sees submission in the review queue.
   Admin approves or rejects.
   - Reject → configuration returns to status=valid+tested; owner may revise and resubmit.
   - Approve →
       a. Version auto-assigned: YYYYMM-NN (publication month; NN incremented if taken)
       b. Configuration becomes public + read-only
       c. Owner's private copy is removed
       d. If the private copy was active at the time of approval,
          the owner is automatically subscribed to the new public version
```

### 8c. Subscription flow

```
1. User browses marketplace (Server UI).
2. User clicks Subscribe on a public valid configuration.
3. A row is created in the subscriptions table: (user_id, config_id).
   No data is copied. The subscription is immediately active.
4. Daemon routes matching emails for this user using the public config's Channels + Headers.
5. Chrome extension syncs subscriptions and shows the config (with its Prompt, read-only).
```

### 8d. Update flow (subscriptions)

```
1. A newer version of a subscribed configuration's name is published (by any user).
2. Subscriber sees notification on dashboard and in Chrome extension.
3. User clicks Update.
4. The subscriptions row is updated to reference the new config_id.
   No data is copied. Previous subscription row is replaced.
```

### 8e. Deactivation / unsubscription / deletion

```
Deactivate (private config):
  Configuration remains valid but daemon stops routing; client stops polling.
  Can be reactivated at any time.

Unsubscribe (public config):
  The subscriptions row is deleted.
  User retains no local artefacts.
  Can re-subscribe at any time.

Delete private config (owner):
  Allowed from any private status.
  Removes configuration, Channels, Headers, and Prompt.

Delete public config (admin only):
  Removes the configuration from the public registry.
  All subscription rows referencing it are cascade-deleted.
  Clients detect the orphan during their next sync and remove local data.
```

---

## 9. Data Model Supplements

> Implementation detail lives in `ARCHITECTURE.md §5`. This section states intent.

### 9.1 Data Residency

**Prompt**
Stored at the daemon (not client-local), as `{url, selector}` JSON,
associated with the configuration row.
Authored in the Chrome extension; pushed via REST API.
For subscriptions: the public config's Prompt is served read-only to subscribers.
For private configs: the owner may update the Prompt at any time.

### 9.2 DB Schema

**Private configurations**
One row per configuration in the `configurations` table.
`visibility=private`, `version=-1`.
Mutable; owned by one user.

**Public configurations**
One row in the `configurations` table.
`visibility=public`, `version=YYYYMM-NN`.
Immutable after publication. Owned by the publishing user but accessible to all.

**Subscriptions**
A separate join table: `(user_id, config_id)`.
Many-to-many: one user may subscribe to many public configs;
one public config may have many subscribers.
No data is copied on subscribe. Subscribing is always active.

---

## 10. Marketplace

- Lists all public valid configurations
- Shows subscriber count per version `[admin]`
- If fewer than 3 subscribers: shows subscriber usernames `[admin]`
- Provides approve / reject actions for pending submissions `[admin]`
- Deletion of a public configuration is available here (see §8e) `[admin]`

### 10.2 Subscriber count `[admin]`

Each public configuration version displays the total number of active subscribers.
This count is visible only to admin users in the marketplace view.

### 10.3 Subscriber names `[admin]`

When a configuration has fewer than 3 subscribers, the subscriber usernames are
displayed alongside the count. Once a configuration reaches 3 or more subscribers,
only the count is shown (usernames are not listed).
