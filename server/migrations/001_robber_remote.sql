CREATE TABLE IF NOT EXISTS `robber_agents` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT,
  `ad_stats_id` bigint UNSIGNED NOT NULL,
  `credential_hash` binary(32) NOT NULL,
  `computer_name` varchar(128) NOT NULL,
  `agent_version` varchar(64) NOT NULL,
  `status` enum('ONLINE','OFFLINE','DISABLED') NOT NULL DEFAULT 'OFFLINE',
  `enrolled_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `last_seen_at` datetime(3) DEFAULT NULL,
  `created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_robber_agents_ad_stats` (`ad_stats_id`),
  UNIQUE KEY `uq_robber_agents_credential` (`credential_hash`),
  KEY `idx_robber_agents_status_seen` (`status`,`last_seen_at`),
  CONSTRAINT `fk_robber_agents_ad_stats`
    FOREIGN KEY (`ad_stats_id`) REFERENCES `ad_stats` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `robber_jobs` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT,
  `agent_id` bigint UNSIGNED NOT NULL,
  `operation` varchar(64) NOT NULL,
  `params_json` json NOT NULL,
  `status` enum('QUEUED','LEASED','RUNNING','COMPLETE','FAILED','CANCELLED')
    NOT NULL DEFAULT 'QUEUED',
  `lease_until` datetime(3) DEFAULT NULL,
  `heartbeat_at` datetime(3) DEFAULT NULL,
  `started_at` datetime(3) DEFAULT NULL,
  `completed_at` datetime(3) DEFAULT NULL,
  `error_code` varchar(64) DEFAULT NULL,
  `error_message` varchar(1024) DEFAULT NULL,
  `created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_robber_jobs_queue` (`agent_id`,`status`,`created_at`),
  KEY `idx_robber_jobs_lease` (`status`,`lease_until`),
  CONSTRAINT `fk_robber_jobs_agent`
    FOREIGN KEY (`agent_id`) REFERENCES `robber_agents` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `robber_reports` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT,
  `job_id` bigint UNSIGNED NOT NULL,
  `agent_id` bigint UNSIGNED NOT NULL,
  `ad_stats_id` bigint UNSIGNED NOT NULL,
  `report_json` json NOT NULL,
  `summary_json` json DEFAULT NULL,
  `content_sha256` binary(32) NOT NULL,
  `created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_robber_reports_job` (`job_id`),
  KEY `idx_robber_reports_agent_created` (`agent_id`,`created_at`),
  KEY `idx_robber_reports_ad_stats_created` (`ad_stats_id`,`created_at`),
  CONSTRAINT `fk_robber_reports_job`
    FOREIGN KEY (`job_id`) REFERENCES `robber_jobs` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_robber_reports_agent`
    FOREIGN KEY (`agent_id`) REFERENCES `robber_agents` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_robber_reports_ad_stats`
    FOREIGN KEY (`ad_stats_id`) REFERENCES `ad_stats` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `robber_api_rate_limits` (
  `rate_key` binary(32) NOT NULL,
  `window_started_at` datetime(3) NOT NULL,
  `request_count` int UNSIGNED NOT NULL,
  PRIMARY KEY (`rate_key`),
  KEY `idx_robber_rate_window` (`window_started_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
