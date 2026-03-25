ALTER TABLE `login_challenges` ADD COLUMN `authenticated_user_id` text;
ALTER TABLE `login_challenges` ADD COLUMN `mfa_state` text NOT NULL DEFAULT 'none';
ALTER TABLE `login_challenges` ADD COLUMN `mfa_attempt_count` integer NOT NULL DEFAULT 0;
ALTER TABLE `login_challenges` ADD COLUMN `enrollment_attempt_count` integer NOT NULL DEFAULT 0;
ALTER TABLE `login_challenges` ADD COLUMN `totp_enrollment_secret_encrypted` text;
