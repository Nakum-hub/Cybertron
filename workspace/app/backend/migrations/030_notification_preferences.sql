-- P2-9: Notification preferences table
CREATE TABLE IF NOT EXISTS notification_preferences (
  user_id           BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  email_on_critical BOOLEAN NOT NULL DEFAULT true,
  email_on_high     BOOLEAN NOT NULL DEFAULT false,
  email_on_resolved BOOLEAN NOT NULL DEFAULT false,
  in_app_all        BOOLEAN NOT NULL DEFAULT true,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
