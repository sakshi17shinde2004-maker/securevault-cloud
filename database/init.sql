-- Run once as MySQL root. Tables are created automatically by the backend on first start.
CREATE DATABASE IF NOT EXISTS securevault_db
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'securevault'@'localhost' IDENTIFIED BY 'SecureVault_123';
GRANT ALL PRIVILEGES ON securevault_db.* TO 'securevault'@'localhost';
FLUSH PRIVILEGES;
