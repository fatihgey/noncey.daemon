# C:\Claude — Global Project Preferences

## noncey admin UI — Style guide

### Rule 1 — Delete button alignment in button rows

When a row of action buttons contains a destructive/delete button alongside non-destructive ones, the delete button must be **right-aligned** while all other buttons remain left-aligned.

Implementation: use a flex container (`display:flex; gap:.5rem;`) on the button row and apply `margin-left:auto` to the delete/danger button. Do not change button order in the source — keep delete last.

Applies to every form or control bar that mixes a `btn-danger` with other buttons, e.g.:

- `/auth/account/password` — Delete account vs Change password
- `/auth/admin/users/(id)/edit` — Delete user vs Save / Cancel
- `/auth/unmatched/(id)` — Dismiss vs Create channel / Back
- `/auth/configs/(id)` — Delete vs Edit / Activate

### Rule 2 — Clickable table rows

In any listing table where rows represent navigable items, the entire row must be clickable and navigate to the detail/edit view (or read-only view in a read-only context). This replaces dedicated "Inspect", "View", or "Edit" link buttons in the actions column.

Implementation: add `style="cursor:pointer;" onclick="location.href='…'"` to the `<tr>`. Any action button that should *not* trigger the row navigation (e.g. Delete, Dismiss) must be in a `<td onclick="event.stopPropagation()">` or have `onclick="event.stopPropagation()"` on the element itself.

---

---
