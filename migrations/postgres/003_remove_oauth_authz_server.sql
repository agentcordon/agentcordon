-- Remove OAuth Authorization Server tables (v1.15.0).
-- The OAuth2 client credentials proxy is unaffected.
DROP TABLE IF EXISTS oauth_authorization_codes;
DROP TABLE IF EXISTS servers;
