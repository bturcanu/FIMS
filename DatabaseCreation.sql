-- Create the database
CREATE DATABASE FileIntegrityDB;

-- Use the newly created database
USE FileIntegrityDB;

-- Create the table with a computed column for file_path hash
-- File path 450 limit (900 bytes)
CREATE TABLE FileBaselines (
    id INT PRIMARY KEY IDENTITY(1,1),
    file_path NVARCHAR(512) NOT NULL,
    file_path_hash AS HASHBYTES('SHA2_256', file_path) PERSISTED UNIQUE,
    file_hash_sha256 NVARCHAR(128) NOT NULL,
    last_checked DATETIME NOT NULL,
    last_modified DATETIME NOT NULL
);

CREATE UNIQUE INDEX idx_filepath_hash ON FileBaselines(file_path_hash);

CREATE TABLE MalwareHashes (
    SHA256Hash CHAR(64) PRIMARY KEY,
    DateAdded DATE,
);

