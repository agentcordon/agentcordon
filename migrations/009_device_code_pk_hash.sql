-- RFC 8628 extension: bind the workspace's public_key_hash at device_code
-- issue time so the approver can verify the request came from the same key
-- that initiated the device authorization grant.
--
-- The broker sends `public_key_hash` on POST /oauth/device/code and must
-- re-present it on POST /oauth/device/approve. A mismatch is a hard 400.
-- This defense-in-depth binding prevents a malicious approver (even one
-- holding a stolen session) from silently attaching a different signing
-- identity to the workspace being provisioned.

ALTER TABLE device_codes ADD COLUMN pk_hash_prefill TEXT;
