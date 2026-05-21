const corsTablesSQL = `
CREATE TABLE IF NOT EXISTS cors_origins (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  label VARCHAR(120) NOT NULL,
  origin VARCHAR(255) NOT NULL,
  description TEXT,
  status ENUM('online','offline') DEFAULT 'online',
  policy ENUM('allow','block') DEFAULT 'allow',
  created_by_user_id BIGINT UNSIGNED NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_cors_origin (origin),
  INDEX idx_cors_status_policy (status, policy),
  FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;
`;

module.exports = { corsTablesSQL };
