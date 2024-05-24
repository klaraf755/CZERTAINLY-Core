ALTER TABLE certificate ADD UNIQUE ("fingerprint");
ALTER TABLE certificate_content ADD UNIQUE ("fingerprint");
ALTER TABLE certificate_request ADD UNIQUE ("fingerprint");
