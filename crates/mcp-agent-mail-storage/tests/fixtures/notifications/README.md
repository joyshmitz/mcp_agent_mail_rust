Notification signal fixtures (legacy parity).

- signal_include_metadata_true.json: with message metadata present (include_metadata=true).
- signal_include_metadata_false.json: no message field (include_metadata=false or metadata missing).
- list_pending_signals_all.json: combined list example including a corrupted signal file entry.

Notes:
- timestamps are placeholders; tests should accept any valid ISO-8601 UTC string from datetime.now(timezone.utc).isoformat().
- list_pending_signals returns raw JSON for valid signals and a minimal error object for corrupted files.
