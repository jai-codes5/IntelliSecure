CREATE DATABASE IF NOT EXISTS intellisecure_db;
USE intellisecure_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'Employee'
);

-- Initial Dummy Data (Password for all is 'password123')
-- Hashed value of 'password123' using bcrypt
INSERT INTO users (username, hashed_password, role) VALUES 
('admin_user', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36XQV.pGZt9N.7G5.R/Rbe6', 'Admin'),
('manager_user', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36XQV.pGZt9N.7G5.R/Rbe6', 'Manager'),
('employee_user', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36XQV.pGZt9N.7G5.R/Rbe6', 'Employee')
ON DUPLICATE KEY UPDATE id=id;