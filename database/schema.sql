
CREATE DATABASE IF NOT EXISTS phishlens_db;
USE phishlens_db;

CREATE TABLE IF NOT EXISTS phishing_urls (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    label VARCHAR(30) NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS analysis_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    url TEXT NOT NULL,
    risk_score INT NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    explanation JSON NOT NULL,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO phishing_urls (url, label, notes) VALUES
('https://www.wikipedia.org', 'legitimate',
 'Illustrative example only'),
('https://www.python.org', 'legitimate',
 'Illustrative example only'),
('http://secure-login-account-update.example.com',
 'phishing', 'Synthetic example'),
('http://verify-wallet-password.example.net',
 'phishing', 'Synthetic example');

SELECT * FROM phishing_urls;
