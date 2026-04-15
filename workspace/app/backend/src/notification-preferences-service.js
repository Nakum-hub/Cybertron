/**
 * P2-9: Notification Preferences Service
 *
 * CRUD for per-user notification preferences.
 */

const { query } = require('./database');
const { ServiceError } = require('./auth-service');

async function getNotificationPreferences(config, userId) {
  const result = await query(
    config,
    `SELECT user_id, email_on_critical, email_on_high, email_on_resolved, in_app_all, created_at, updated_at
     FROM notification_preferences
     WHERE user_id = $1`,
    [Number(userId)]
  );

  if (!result?.rows?.length) {
    // Return defaults
    return {
      userId: String(userId),
      emailOnCritical: true,
      emailOnHigh: false,
      emailOnResolved: false,
      inAppAll: true,
    };
  }

  const row = result.rows[0];
  return {
    userId: String(row.user_id),
    emailOnCritical: row.email_on_critical,
    emailOnHigh: row.email_on_high,
    emailOnResolved: row.email_on_resolved,
    inAppAll: row.in_app_all,
  };
}

async function upsertNotificationPreferences(config, userId, prefs) {
  if (!userId) {
    throw new ServiceError(400, 'invalid_user_id', 'User ID is required.');
  }

  const emailOnCritical = prefs.emailOnCritical !== undefined ? Boolean(prefs.emailOnCritical) : true;
  const emailOnHigh = prefs.emailOnHigh !== undefined ? Boolean(prefs.emailOnHigh) : false;
  const emailOnResolved = prefs.emailOnResolved !== undefined ? Boolean(prefs.emailOnResolved) : false;
  const inAppAll = prefs.inAppAll !== undefined ? Boolean(prefs.inAppAll) : true;

  const result = await query(
    config,
    `INSERT INTO notification_preferences (user_id, email_on_critical, email_on_high, email_on_resolved, in_app_all, updated_at)
     VALUES ($1, $2, $3, $4, $5, NOW())
     ON CONFLICT (user_id) DO UPDATE SET
       email_on_critical = EXCLUDED.email_on_critical,
       email_on_high = EXCLUDED.email_on_high,
       email_on_resolved = EXCLUDED.email_on_resolved,
       in_app_all = EXCLUDED.in_app_all,
       updated_at = NOW()
     RETURNING user_id, email_on_critical, email_on_high, email_on_resolved, in_app_all`,
    [Number(userId), emailOnCritical, emailOnHigh, emailOnResolved, inAppAll]
  );

  const row = result?.rows?.[0];
  return {
    userId: String(row.user_id),
    emailOnCritical: row.email_on_critical,
    emailOnHigh: row.email_on_high,
    emailOnResolved: row.email_on_resolved,
    inAppAll: row.in_app_all,
  };
}

module.exports = {
  getNotificationPreferences,
  upsertNotificationPreferences,
};
