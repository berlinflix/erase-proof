# Ubuntu Trash and permanent deletion

Ubuntu file-manager Delete usually moves the item to Trash. Its contents are
still allocated. Choose **Recover files → Browse Ubuntu Trash** to copy a listed
item into a new recovery folder. Files of any extension and directory trees are
supported. The original path is displayed; copying never writes to that path,
removes the Trash entry or overwrites an existing destination.

The desktop inspects the current user's home Trash under `$XDG_DATA_HOME/Trash`
(normally `~/.local/share/Trash`). Another mounted volume can have its own store.
Select that store explicitly through the CLI:

```bash
eraseproof trash-list
eraseproof trash-list --trash-root /media/YOUR_VOLUME/.Trash-1000
eraseproof trash-recover EXACT_ITEM_ID --output ~/EraseProof/trash-copy
```

Use `--trash-root` on `trash-recover` as well for a nondefault store. IDs come
from `trash-list`. Source files/directories are opened through directory
descriptors; symlinks, special files and cross-filesystem trees are refused.
Copies are streamed, SHA-256 measured, flushed, and accompanied by recovery JSON.
Cancellation or errors leave an explicitly incomplete report. The application
does not preserve original permissions, owners or special file semantics.

Shift+Delete, `rm`, emptying Trash and other permanent deletion require the
separate disk/image recovery engine. Stop writes to that filesystem and use an
offline source or image, saving recovered output to another disk. Reused blocks,
discard/TRIM, encryption and overwritten metadata can make recovery impossible.
Root access is needed to read most raw Linux disks; the unprivileged desktop
does not silently elevate. Boot the supplied live environment or use the CLI
with explicit administrator permissions for raw acquisition/recovery.

Tests include an actual `gio trash` operation on a fresh randomly filled file,
exact recovery without a format signature, Unicode paths, directory trees,
invalid metadata, cancellation, symlink refusal and the native Qt selection flow.

Format reference: [Freedesktop Trash specification](https://specifications.freedesktop.org/trash/1.0/).
