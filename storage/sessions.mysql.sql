
-- Presets
SET @_SQL_MODE = @@SQL_MODE;-- --
SET SQL_MODE = ( SELECT CONCAT( @@SQL_MODE, ',TRADITIONAL' ) );-- --


-- Sessions based on currently visiting site
CREATE TABLE sessions(
	id SERIAL PRIMARY KEY,
	basename VARCHAR( 255 ) NOT NULL,
	session_id VARCHAR( 50 ),
	session_ip VARCHAR( 50 ),
	session_data MEDIUMTEXT,
	created DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	expires DATETIME,
	
	CONSTRAINT uk_session_basename UNIQUE ( basename, session_id )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;-- --
CREATE INDEX idx_session_site ON sessions( basename );-- --
CREATE INDEX idx_session_ip ON sessions( session_ip );-- --
CREATE INDEX idx_session_created ON sessions( created DESC );-- --
CREATE INDEX idx_session_updated ON sessions( updated DESC );-- --
CREATE INDEX idx_session_expires ON sessions( expires ASC );-- --

CREATE VIEW ip_view AS
SELECT 
	id, basename, session_id, session_ip, created, updated, expires, 
	CASE 
		WHEN session_ip REGEXP '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$' THEN 'IPv4' 
		WHEN session_ip REGEXP '^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$' THEN 'IPv6' 
		WHEN session_ip REGEXP '^(([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}|::)$' THEN 'IPv6' 
		ELSE 'Unknown'
	END AS ip_type
FROM sessions;-- --

CREATE TABLE user_agents (
	session_id VARCHAR( 50 ) PRIMARY KEY,
	session_ua TEXT NOT NULL,
	FULLTEXT ( session_ua )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;-- --

DELIMITER $$
CREATE TRIGGER session_before_insert BEFORE INSERT ON sessions FOR EACH ROW
BEGIN 
	IF NEW.session_id IS NULL THEN 
		SET NEW.session_id = UUID();
	END IF;
END $$
DELIMITER ;
-- --

DELIMITER $$
CREATE TRIGGER session_before_update BEFORE UPDATE ON sessions FOR EACH ROW
BEGIN 
	IF NEW.session_id IS NULL THEN 
		SET NEW.session_id = UUID();
	END IF;
END $$
DELIMITER ;
-- --

SET SQL_MODE = @_SQL_MODE;

