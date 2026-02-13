# Checks Workspace TUI

The checks workspace TUI is designed for fast operations on large check catalogs.

## Launch

```bash
# Interactive terminals
governor checks

# Explicit command
governor checks tui
```

Fallback behavior:
- In non-interactive shells (for example CI), `governor checks` runs `governor checks list`.

## Core Navigation

- `j` / `k`: move selection
- `g` / `G`: jump top/bottom
- `pgup` / `pgdown`: page navigation
- `/`: search mode
- `x`: clear search + filters

## Filters and Sorting

- `s`: cycle status filter (`all -> enabled -> draft -> disabled`)
- `o`: cycle source filter (`all -> custom -> builtin`)
- `1`: sort by id
- `2`: sort by status
- `3`: sort by source
- `4`: sort by severity
- `5`: sort by path

Repeating the same sort key toggles ascending/descending order.

## Safe Actions (v1)

- `e`: enable selected mutable custom check (requires confirmation)
- `d`: disable selected mutable custom check (requires confirmation)
- `n`: duplicate selected check into write target as `draft`
- `p`: show selected check file path
- `r`: reload checks from disk

Guardrails:
- Built-in, shadowed, and invalid rows are read-only for status changes.
- Invalid check files are not duplicable.

## Details and Exit

- `h`: toggle details panel
- `q`: quit
