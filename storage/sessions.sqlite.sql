
-- GUID/UUID generator helper
CREATE VIEW uuid AS SELECT lower(
	hex( randomblob( 4 ) ) || '-' || 
	hex( randomblob( 2 ) ) || '-' || 
	'4' || substr( hex( randomblob( 2 ) ), 2 ) || '-' || 
	substr( 'AB89', 1 + ( abs( random() ) % 4 ) , 1 )  ||
	substr( hex( randomblob( 2 ) ), 2 ) || '-' || 
	hex( randomblob( 6 ) )
) AS id;-- --

-- Sessions based on currently visiting site
CREATE TABLE sessions(
	id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	basename TEXT NOT NULL COLLATE NOCASE,
	session_id TEXT DEFAULT NULL COLLATE NOCASE,
	session_ip TEXT DEFAULT NULL COLLATE NOCASE,
	session_data TEXT DEFAULT NULL COLLATE NOCASE,
	created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires DATETIME DEFAULT NULL
) WITHOUT ROWID;-- --
CREATE UNIQUE INDEX idx_session_id ON sessions( basename, session_id )
	WHERE session_id IS NOT NULL;-- --
CREATE INDEX idx_session_site ON sessions( basename );-- --
CREATE INDEX idx_session_ip ON sessions( session_ip ) 
	WHERE session_ip IS NOT NULL;-- --
CREATE INDEX idx_session_created ON sessions( created DESC );-- --
CREATE INDEX idx_session_updated ON sessions( updated DESC );-- --
CREATE INDEX idx_session_expires ON sessions( expires ASC )
	WHERE expires IS NOT NULL;-- --

CREATE VIEW ip_view AS
SELECT 
	id, basename, session_id, session_ip, created, updated, expires, 
	CASE 
		WHEN session_ip LIKE '%.%.%.%' AND 
			INSTR( session_ip, '.' ) > 0 AND
			LENGTH( session_ip ) - LENGTH( REPLACE( session_ip, '.', '' ) ) = 3 THEN 'IPv4' 
		WHEN session_ip LIKE '%:%' THEN 'IPv6'
		ELSE 'Unknown'
	END AS ip_type
FROM sessions;-- --

CREATE VIRTUAL TABLE user_agents 
	USING fts4( 
		session_id, 
		session_ua, 
		tokenize=unicode61 
	);-- --

CREATE TRIGGER session_insert AFTER INSERT ON sessions FOR EACH ROW
WHEN NEW.session_id IS NULL
BEGIN
	UPDATE sessions SET session_id = ( SELECT id FROM uuid ) 
		WHERE id = NEW.id;
END;-- --

CREATE TRIGGER session_update AFTER UPDATE ON sessions
BEGIN
	UPDATE sessions SET updated = CURRENT_TIMESTAMP 
		WHERE id = NEW.id;
END;

