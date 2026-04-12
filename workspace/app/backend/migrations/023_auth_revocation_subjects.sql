-- Preserve non-numeric JWT subjects in revocation persistence without losing numeric FK support.
ALTER TABLE auth_access_token_revocations
  ADD COLUMN IF NOT EXISTS user_subject VARCHAR(191);

UPDATE auth_access_token_revocations
SET user_subject = user_id::TEXT
WHERE user_id IS NOT NULL
  AND user_subject IS NULL;

CREATE INDEX IF NOT EXISTS auth_access_token_revocations_user_subject_idx
  ON auth_access_token_revocations (tenant_slug, user_subject)
  WHERE user_subject IS NOT NULL;
