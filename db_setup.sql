CREATE DATABASE IF NOT EXISTS file_transfer_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE file_transfer_db;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(80) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('user','admin') DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transfers (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  filename VARCHAR(255),
  stored_name VARCHAR(255),
  nonce VARBINARY(16),
  tag VARBINARY(16),
  filesize BIGINT,
  transfer_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
