-- One lifecycle field for workspaces.
--
-- `enabled` and `status` were two flags for one thing, and they disagreed:
-- a workspace could be enabled and revoked, or disabled and active, and each
-- code path checked whichever it remembered. `status` now carries the whole
-- lifecycle: pending, active, disabled, revoked. Rows that were switched off
-- become `disabled`; revoked rows stay revoked. The `enabled` column is kept
-- in step with the status for readers of the old schema and is no longer
-- read by the server.

UPDATE workspaces SET status = 'disabled' WHERE enabled = 0 AND status = 'active';
UPDATE workspaces SET enabled = CASE WHEN status = 'active' THEN 1 ELSE 0 END;
