-- Migration 010: Rename sidecar -> device (PostgreSQL)
-- Renames tables and columns from the legacy "sidecar" naming to "device".

ALTER TABLE sidecars RENAME TO devices;
ALTER TABLE sidecar_used_jtis RENAME TO device_used_jtis;
ALTER TABLE device_used_jtis RENAME COLUMN sidecar_id TO device_id;

-- Rename indexes
ALTER INDEX IF EXISTS idx_sidecar_jtis_expires RENAME TO idx_device_jtis_expires;
