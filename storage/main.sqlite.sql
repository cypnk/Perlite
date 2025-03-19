

-- Helper view


-- Generate a random unique string
CREATE VIEW rnd AS SELECT lower( hex( randomblob( 16 ) ) ) AS id;-- --


-- GUID/UUID generator helper
CREATE VIEW uuid AS SELECT lower(
	hex( randomblob( 4 ) ) || '-' || 
	hex( randomblob( 2 ) ) || '-' || 
	'4' || substr( hex( randomblob( 2 ) ), 2 ) || '-' || 
	substr( 'AB89', 1 + ( abs( random() ) % 4 ) , 1 )  ||
	substr( hex( randomblob( 2 ) ), 2 ) || '-' || 
	hex( randomblob( 6 ) )
) AS id;-- --



-- Software tracking



-- Update/upgrade tracking
CREATE TABLE versions (
	version_id INTEGER PRIMARY KEY AUTOINCREMENT,
	installed TEXT NOT NULL,
	created DATETIME DEFAULT CURRENT_TIMESTAMP,
	
	CONSTRAINT uk_versions_installed UNIQUE ( installed )
);-- --



-- Main content and user details



-- Configuration settings
CREATE TABLE config (
	setting_id INTEGER PRIMARY KEY AUTOINCREMENT,
	label TEXT NOT NULL COLLATE NOCASE,
	settings TEXT COLLATE NOCASE,
	
	CONSTRAINT uk_config_label UNIQUE ( label )
);-- --

-- Domains and paths
CREATE TABLE realms (
	realm_id INTEGER PRIMARY KEY AUTOINCREMENT,
	basename TEXT NOT NULL DEFAULT 'localhost' COLLATE NOCASE,
	basepath TEXT NOT NULL DEFAULT '/' COLLATE NOCASE,
	is_active INTEGER NOT NULL DEFAULT 1 
		CHECK ( is_active IN ( 0, 1 ) ),
	is_maintenance INTEGER NOT NULL DEFAULT 0 
		CHECK ( is_maintenance IN ( 0, 1 ) ),
	-- Referenced preset settings
	setting_id INTEGER,
	-- Custom settings serialized JSON
	settings_override TEXT COLLATE NOCASE,
	
	CONSTRAINT uk_realms_realm_path UNIQUE ( basename, basepath ),
	FOREIGN KEY ( setting_id ) REFERENCES config ( setting_id ) ON DELETE SET NULL
);-- --
CREATE INDEX idx_realm_basename ON realms ( basename );-- --
CREATE INDEX idx_realm_basepath ON realms( basepath );-- --
CREATE INDEX idx_realm_setting ON realms ( setting_id );-- --



-- List of languages
CREATE TABLE languages (
	language_id INTEGER PRIMARY KEY AUTOINCREMENT,
	label TEXT NOT NULL COLLATE NOCASE,
	iso_code TEXT NOT NULL COLLATE NOCASE,
	
	-- English name
	eng_name TEXT NOT NULL COLLATE NOCASE,
	lang_group TEXT DEFAULT NULL COLLATE NOCASE,
	
	setting_id INTEGER DEFAULT NULL,
	settings_override TEXT COLLATE NOCASE,
	
	FOREIGN KEY ( setting_id ) REFERENCES config ( setting_id ) ON DELETE SET NULL
);-- --
CREATE UNIQUE INDEX idx_lang_label ON languages ( label );-- --
CREATE UNIQUE INDEX idx_lang_iso ON languages ( iso_code );-- --
CREATE UNIQUE index idx_lang_eng ON languages ( eng_name );-- --
CREATE INDEX idx_lang_group ON languages ( lang_group )
	WHERE lang_group IS NOT NULL;-- --
CREATE INDEX idx_lang_settings ON languages ( setting_id ) 
	WHERE setting_id IS NOT NULL;-- --

-- Performant metadata and generated info that doesn't change the content
CREATE TABLE lang_meta(
	lang_meta_id INTEGER PRIMARY KEY AUTOINCREMENT,
	language_id INTEGER NOT NULL,
	
	-- Default interface language
	is_default INTEGER NOT NULL DEFAULT 0
		CHECK ( is_default IN ( 0, 1 ) ),
	sort_order INTEGER NOT NULL DEFAULT 0,
	
	FOREIGN KEY ( language_id ) REFERENCES languages ( language_id ) ON DELETE CASCADE
);-- --
CREATE UNIQUE INDEX idx_lang_meta ON lang_meta ( language_id );-- --
CREATE INDEX idx_lang_default ON lang_meta ( is_default );-- --
CREATE INDEX idx_lang_sort ON lang_meta ( sort_order );-- --

CREATE TRIGGER lang_after_insert AFTER INSERT ON languages FOR EACH ROW
BEGIN
	INSERT INTO lang_meta( language_id ) VALUES ( NEW.language_id );
END;-- --

-- Unset previous default language if new default is set
CREATE TRIGGER lang_default_update BEFORE UPDATE ON lang_meta FOR EACH ROW 
WHEN NEW.is_default = 1
BEGIN
	UPDATE languages SET is_default = 0 
		WHERE is_default IS NOT 0 
		AND language_meta_id IS NOT NEW.language_meta_id;
END;-- --



-- User accounts
CREATE TABLE users (
	user_id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL COLLATE NOCASE,
	password_hash TEXT NOT NULL,
	title TEXT COLLATE NOCASE,
	email TEXT COLLATE NOCASE,
	
	CONSTRAINT uk_users_username UNIQUE ( username )
);-- --
CREATE INDEX idx_user_title ON users ( title );-- --
CREATE UNIQUE INDEX idx_user_email ON users ( email ) 
	WHERE email IS NOT NULL;-- --

CREATE TABLE user_meta (
	user_meta_id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	uuid TEXT,
	is_enabled INTEGER DEFAULT 0 
		CHECK ( is_enabled IN ( 0, 1 ) ),
	created DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated DATETIME DEFAULT CURRENT_TIMESTAMP,
	setting_id INTEGER,
	settings_override TEXT COLLATE NOCASE,
	
	FOREIGN KEY ( user_id ) REFERENCES users ( user_id ) ON DELETE CASCADE,
	FOREIGN KEY ( setting_id ) REFERENCES config ( setting_id ) ON DELETE SET NULL
);-- --
CREATE INDEX idx_user_uuid ON user_meta ( uuid )
	WHERE uuid IS NOT NULL;-- --
CREATE INDEX idx_user_enabled ON user_meta ( is_enabled );-- --
CREATE INDEX idx_user_created ON user_meta ( created );-- --
CREATE INDEX idx_user_updated ON user_meta ( updated );-- --
CREATE INDEX idx_user_settings ON user_meta ( setting_id ) 
	WHERE setting_id IS NOT NULL;-- --

-- Custom user data
CREATE TABLE user_fields (
	user_id INTEGER NOT NULL,
	field_name TEXT NOT NULL,
	field_value TEXT NOT NULL,
	
	PRIMARY KEY ( user_id, field_name ),
	FOREIGN KEY ( user_id ) REFERENCES users ( user_id ) ON DELETE CASCADE
);-- --
CREATE INDEX idx_user_field_user ON user_fields ( user_id );-- --
CREATE INDEX idx_user_field ON user_fields ( field_name );-- --

-- Authentication
CREATE TABLE logins (
	user_id INTEGER PRIMARY KEY,
	realm_id INTEGER NOT NULL,
	lookup TEXT,
	is_active INTEGER DEFAULT 0 
		CHECK ( is_active IN ( 0, 1 ) ),
	current_login DATETIME,
	last_login DATETIME
);-- --
CREATE INDEX idx_login_realm ON logins ( realm_id );-- --
CREATE UNIQUE INDEX idx_login_lookup ON logins ( lookup ) 
	WHERE lookup IS NOT NULL;-- --
CREATE INDEX idx_login_active ON logins ( is_active );-- --
CREATE INDEX idx_login_current ON logins ( current_login ) 
	WHERE current_login IS NOT NULL;-- --
CREATE INDEX idx_login_last ON logins ( last_login ) 
	WHERE last_login IS NOT NULL;-- --

CREATE VIEW user_auth_view AS SELECT 
	logins.user_id AS user_id,
	logins.lookup AS lookup,
	logins.realm_id AS realm_id,
	logins.is_active AS is_active,
	logins.last_login AS last_login,
	logins.current_login AS current_login,
	
	users.username AS username,
	users.password_hash AS password_hash,
	
	meta.is_enabled AS is_enabled,
	COALESCE( config.settings, '{}' ) AS settings,
	meta.settings_override AS settings_override
	
	FROM logins
	LEFT JOIN users ON logins.user_id = users.user_id
	LEFT JOIN user_meta meta ON logins.user_id = meta.user_id
	LEFT JOIN config ON meta.setting_id = config.setting_id;-- --

CREATE TRIGGER user_after_insert AFTER INSERT ON users FOR EACH ROW 
BEGIN
	INSERT INTO user_meta ( user_id, uuid ) 
		VALUES ( NEW.user_id, ( SELECT id FROM uuid ) );
	
	INSERT INTO logins ( user_id ) VALUES ( NEW.user_id );
END;-- --

CREATE TRIGGER user_after_update AFTER UPDATE ON users FOR EACH ROW
BEGIN
	UPDATE user_meta SET updated = CURRENT_TIMESTAMP
		WHERE user_id = NEW.user_id;
END;-- --

-- Login
CREATE TRIGGER auth_action_login BEFORE UPDATE ON logins FOR EACH ROW 
WHEN NEW.is_active = 1
BEGIN
	UPDATE logins SET 
		lookup = ( SELECT id FROM rnd ), 
		last_login = 
			COALESCE( 
				OLD.current_login, 
				OLD.last_login, 
				CURRENT_TIMESTAMP
			),
		current_login = CURRENT_TIMESTAMP
	WHERE user_id = NEW.user_id;
END;-- --

-- Logout
CREATE TRIGGER auth_action_logout BEFORE UPDATE ON logins FOR EACH ROW
WHEN NEW.is_active = 0
BEGIN
	UPDATE logins SET lookup = NULL WHERE user_id = NEW.user_id;
END;-- --


CREATE VIEW user_field_view AS SELECT 
	fields.field_name AS field_name,
	fields.field_value AS field_value
	
	FROM users
	LEFT JOIN user_fields fields ON users.user_id = fields.user_id;-- --

-- Privilege groups
CREATE TABLE roles (
	role_id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL COLLATE NOCASE,
	setting_id INTEGER,
	settings_override TEXT COLLATE NOCASE,
	
	CONSTRAINT uk_name UNIQUE ( name ),
	FOREIGN KEY ( setting_id ) REFERENCES config ( setting_id ) ON DELETE SET NULL
);-- --
CREATE INDEX idx_role_settings ON roles ( setting_id ) 
	WHERE setting_id IS NOT NULL;-- --

CREATE TABLE user_roles (
	role_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	created DATETIME DEFAULT CURRENT_TIMESTAMP,
	
	PRIMARY KEY ( role_id, user_id ),
	FOREIGN KEY ( role_id ) REFERENCES roles ( role_id ) ON DELETE CASCADE,
	FOREIGN KEY ( user_id ) REFERENCES users ( user_id ) ON DELETE CASCADE
);-- --
CREATE INDEX idx_user_roles ON user_roles ( user_id, role_id );-- --
CREATE INDEX idx_user_role_assigned ON user_roles ( created );-- --



-- Content



-- Content entity types
CREATE TABLE node_types (
	node_type_id INTEGER PRIMARY KEY AUTOINCREMENT,
	label TEXT NOT NULL COLLATE NOCASE,
	handler TEXT,
	
	setting_id INTEGER,
	settings_override TEXT COLLATE NOCASE,
	
	CONSTRAINT uk_label UNIQUE ( label ), 
	FOREIGN KEY ( setting_id ) REFERENCES config ( setting_id ) ON DELETE SET NULL
);-- --
CREATE INDEX idx_node_type_handler ON node_types ( handler ) 
	WHERE handler IS NOT NULL;-- --
CREATE INDEX idx_node_type_setting ON node_types ( setting_id )
	WHERE setting_id IS NOT NULL;-- --

-- Content entities
CREATE TABLE nodes (
	node_id INTEGER PRIMARY KEY AUTOINCREMENT,
	node_type_id INTEGER NOT NULL,
	parent_id INTEGER,
	author_id INTEGER,
	title TEXT COLLATE NOCASE,
	
	-- Filtered and formatted content
	rendered TEXT NOT NULL COLLATE NOCASE,
	sort_order INTEGER NOT NULL DEFAULT 0,
	
	FOREIGN KEY ( node_type_id ) REFERENCES node_types ( node_type_id ) ON DELETE RESTRICT,
	FOREIGN KEY ( parent_id ) REFERENCES nodes ( node_id ) ON DELETE SET NULL,
	FOREIGN KEY ( author_id ) REFERENCES users ( user_id ) ON DELETE SET NULL
);-- --
CREATE INDEX idx_node_type ON nodes ( node_type_id );-- --
CREATE INDEX idx_node_parent ON nodes ( parent_id )
	WHERE parent_id IS NOT NULL;-- --
CREATE INDEX idx_node_author ON nodes ( author_id )
	WHERE author_id IS NOT NULL;-- --
CREATE INDEX idx_node_title ON nodes ( title )
	WHERE title IS NOT NULL;-- --
CREATE INDEX idx_node_sort ON nodes ( sort_order );-- --

-- Content metadata
CREATE TABLE node_meta (
	node_meta_id INTEGER PRIMARY KEY AUTOINCREMENT,
	node_id INTEGER NOT NULL,
	uuid TEXT,
	created DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated DATETIME DEFAULT CURRENT_TIMESTAMP,
	published DATETIME,
	hierarchy TEXT,
	
	-- Moved to top when displaying results
	is_pinned INTEGER NOT NULL DEFAULT 1 
		CHECK ( is_pinned IN ( 0, 1 ) ),
	
	-- If true, don't publish regardless of pub date
	is_draft INTEGER NOT NULL DEFAULT 1 
		CHECK ( is_draft IN ( 0, 1 ) ),
	
	-- Allow this node to be addressed by node_id directly
	is_direct INTEGER NOT NULL DEFAULT 0 
		CHECK ( is_direct IN ( 0, 1 ) ),
	
	-- Dynamically generated JSON
	authorship TEXT NOT NULL DEFAULT '{ "authors" : [] }',
	
	setting_id INTEGER,
	settings_override TEXT COLLATE NOCASE,
	
	FOREIGN KEY ( node_id ) REFERENCES nodes ( node_id ) ON DELETE CASCADE,
	FOREIGN KEY ( setting_id ) REFERENCES config ( setting_id ) ON DELETE SET NULL
);-- --
CREATE INDEX idx_node_meta ON node_meta ( node_id );-- --
CREATE INDEX idx_node_uuid ON node_meta ( uuid )
	WHERE uuid IS NOT NULL;-- --
CREATE INDEX idx_node_created ON node_meta ( created ASC );-- --
CREATE INDEX idx_node_updated ON node_meta ( updated DESC )
	WHERE updated IS NOT NULL;-- --
CREATE INDEX idx_node_published ON node_meta ( published DESC )
	WHERE published IS NOT NULL;-- --
CREATE INDEX idx_node_pinned ON node_meta ( is_pinned );-- --
CREATE INDEX idx_node_draft ON node_meta ( is_draft );-- --
CREATE INDEX idx_node_direct ON node_meta ( is_direct );-- --
CREATE INDEX idx_node_settings ON node_meta ( setting_id ) 
	WHERE setting_id IS NOT NULL;-- --

CREATE VIEW node_view AS SELECT 
	nodes.node_id AS node_id,
	nodes.node_type_id AS node_type_id,
	nodes.parent_id AS parent_id,
	nodes.author_id AS author_id,
	nodes.rendered AS rendered,
	nodes.author_id AS node_author_id,
	
	node_users.username AS node_author_name,
	COALESCE( node_users.title, node_users.username ) AS node_author_title,
	
	meta.hierarchy AS hierarchy,
	meta.created AS created,
	meta.updated AS updated,
	meta.published AS published,
	meta.is_direct AS is_direct,
	meta.is_draft AS is_draft,
	meta.is_pinned AS is_pinned,
	
	types.label AS type_label,
	types.handler AS type_handler,
	COALESCE( type_config.settings, '{}' ) AS type_settings,
	types.settings_override AS type_settings_override,
	
	COALESCE( node_config.settings, '{}' ) AS settings,
	meta.settings_override AS settings_override
	
	FROM nodes
	JOIN node_meta meta ON nodes.node_id = meta.node_id
	JOIN node_types types ON nodes.node_type_id = types.node_type_id
	LEFT JOIN config type_config ON types.setting_id = type_config.setting_id
	LEFT JOIN config node_config ON meta.setting_id = node_config.setting_id
	LEFT JOIN users node_users ON nodes.author_id = node_users.user_id;-- --

-- Content sections
CREATE TABLE node_contents (
	node_content_id INTEGER PRIMARY KEY AUTOINCREMENT,
	node_id INTEGER NOT NULL,
	content_name TEXT NOT NULL COLLATE NOCASE,
	content_value TEXT NOT NULL COLLATE NOCASE,
	
	-- Generated
	rendered TEXT NOT NULL COLLATE NOCASE,		-- Template(s) applied
	plain TEXT NOT NULL COLLATE NOCASE,		-- HTML stripped
	
	-- Read-only
	content_format TEXT NOT NULL,
	
	-- Include in full text search table
	is_full_text INTEGER DEFAULT 0 
		CHECK ( is_full_text IN ( 0, 1 ) ),
	
	-- Metadata
	author_id INTEGER,
	editor_id INTEGER,
	language_id INTEGER,
	sort_order INTEGER NOT NULL DEFAULT 0,
	updated DATETIME DEFAULT CURRENT_TIMESTAMP,
	
	CONSTRAINT uk_node_name UNIQUE ( node_id, content_name ),
	FOREIGN KEY ( node_id ) REFERENCES nodes ( node_id ) ON DELETE CASCADE,
	FOREIGN KEY ( author_id ) REFERENCES users ( user_id ) ON DELETE SET NULL,
	FOREIGN KEY ( editor_id ) REFERENCES users ( user_id ) ON DELETE SET NULL,
	FOREIGN KEY ( language_id ) REFERENCES languages ( language_id ) ON DELETE SET NULL
);-- --
CREATE INDEX idx_node_content ON node_contents ( content_name );-- --
CREATE INDEX idx_node_content_node ON node_contents ( node_id );-- --
CREATE INDEX idx_node_content_author ON node_contents ( author_id )
	WHERE author_id IS NOT NULL;-- --
CREATE INDEX idx_node_content_editor ON node_contents ( editor_id )
	WHERE editor_id IS NOT NULL;-- --
CREATE INDEX idx_node_content_language ON node_contents ( language_id )
	WHERE language_id IS NOT NULL;-- --
CREATE INDEX idx_node_content_sort ON node_contents ( sort_order );-- --
CREATE INDEX idx_node_content_updated ON node_contents ( updated );-- --

-- Write-only edit history
CREATE TABLE node_content_revisions (
	node_content_id INTEGER NOT NULL,
	user_id INTEGER,
	language_id INTEGER,
	content_name TEXT NOT NULL,
	content_value TEXT NOT NULL,
	sort_order INTEGER NOT NULL DEFAULT 0,
	revision DATETIME NOT NULL,
	
	FOREIGN KEY ( node_content_id ) 
		REFERENCES node_contents ( node_content_id ) ON DELETE CASCADE
);-- --
CREATE INDEX idx_node_content_revision_content ON node_content_revisions ( node_content_id );-- --
CREATE INDEX idx_node_content_revision ON node_content_revisions ( revision DESC );-- --

CREATE VIEW node_content_view AS SELECT 
	nodes.node_id AS node_id,
	
	nc.content_name AS content_name,
	nc.content_value AS content_value,
	nc.content_format AS content_format,
	nc.sort_order AS sort_order,
	nc.author_id AS content_author_id,
	nc.editor_id AS content_editor_id,
	nc.language_id AS language_id,
	
	content_users.username AS content_author_name,
	COALESCE( content_users.title, content_users.username ) AS content_author_title
	
	FROM nodes
	LEFT JOIN node_contents nc ON nodes.node_id = nc.node_id
	LEFT JOIN users content_users ON nc.author_id = content_users.user_id;-- --


CREATE VIRTUAL TABLE node_search 
	USING fts4( body, tokenize=unicode61 );-- --


-- References
CREATE TABLE links (
	link_id INTEGER PRIMARY KEY AUTOINCREMENT,
	from_node_id INTEGER NOT NULL,
	to_node_id INTEGER NOT NULL,
	
	FOREIGN KEY ( from_node_id ) REFERENCES nodes ( node_id ),
	FOREIGN KEY ( to_node_id ) REFERENCES nodes ( node_id )
);-- --
CREATE INDEX idx_link_reference ON links ( from_node_id, to_node_id );-- --

-- Request
CREATE TABLE node_paths (
	path_id INTEGER PRIMARY KEY AUTOINCREMENT,
	realm_id INTEGER NOT NULL,
	node_id INTEGER NOT NULL,
	slug TEXT NOT NULL,
	
	-- Set as homepage of realm
	is_home INTEGER NOT NULL DEFAULT 0 
		CHECK ( is_home IN ( 0, 1 ) ),
	
	CONSTRAINT uk_realm_node_home UNIQUE ( realm_id, node_id, is_home ),
	FOREIGN KEY ( realm_id ) REFERENCES realms ( realm_id ) ON DELETE CASCADE,
	FOREIGN KEY ( node_id ) REFERENCES nodes ( node_id ) ON DELETE CASCADE
);-- --
CREATE INDEX idx_node_paths ON node_paths ( slug );-- --

-- Path view
CREATE VIEW node_path_view AS SELECT
	realms.basename AS basename,
	realms.basepath AS basepath,
	meta.hierarchy AS hierarchy,
	paths.slug AS slug, 
	paths.is_home AS is_home
	
	FROM node_paths paths
	JOIN node_meta meta ON paths.node_id = meta.node_id
	JOIN realms ON paths.realm_id = realms.realm_id;-- --



-- Path triggers



-- New home
CREATE TRIGGER new_home_insert_node_path_home BEFORE INSERT ON node_paths FOR EACH ROW 
WHEN NEW.is_home = 1
BEGIN
	-- Remove old home before insert
	UPDATE node_paths SET is_home = 0 
		WHERE is_home = 1 AND realm_id = NEW.realm_id;
END;-- --


-- Remove old home before update
CREATE TRIGGER new_home_update_node_path BEFORE UPDATE ON node_paths FOR EACH ROW 
WHEN NEW.is_home = 1
BEGIN
	UPDATE node_paths SET is_home = 0 
		WHERE is_home = 1 
			AND realm_id = NEW.realm_id 
			AND path_id <> NEW.path_id;
END;-- --



-- Content triggers



CREATE TRIGGER node_after_insert AFTER INSERT ON nodes FOR EACH ROW
BEGIN 
	INSERT INTO node_meta ( node_id, uuid ) 
		VALUES ( NEW.node_id, ( SELECT id FROM uuid ) );
END;-- --

CREATE TRIGGER node_after_update AFTER UPDATE ON nodes FOR EACH ROW
BEGIN
	UPDATE node_meta SET updated = CURRENT_TIMESTAMP 
		WHERE node_id = NEW.node_id;
END;-- --

CREATE TRIGGER node_content_after_insert AFTER INSERT ON node_contents FOR EACH ROW
BEGIN
	-- Update rendered node content
	UPDATE nodes SET rendered = ( 
		SELECT GROUP_CONCAT( contents.rendered 
			ORDER BY contents.node_content_id ASC, 
			contents.sort_order ASC 
		) AS html 
		FROM node_contents contents 
			WHERE contents.node_id = NEW.node_id 
	) WHERE nodes.node_id = NEW.node_id;
	
	UPDATE node_meta SET authorship = '{ "authors" : [ ' || ( 
		SELECT GROUP_CONCAT( selection, ',' ) AS authors 
		FROM (
			SELECT ' {' || 
				'"user_id" 	: '	|| users.user_id		|| ', '		||
				'"username"	: "'	|| users.username		|| '", '	|| 
				'"title"	: "'	|| COALESCE( users.title, '' )	|| '", '	|| 
				'"content"	: "'	|| contents.content_name	|| '", '	||  
				'"is_creator"	: 1'	|| 
			' }' AS selection
			
			FROM node_contents contents
			LEFT JOIN users ON contents.author_id = users.user_id
			
			WHERE contents.node_id = NEW.node_id
			GROUP BY users.user_id
			ORDER BY contents.sort_order
		)
	) || ' ] }', updated = CURRENT_TIMESTAMP WHERE node_id = NEW.node_id;
END;-- --

CREATE TRIGGER node_content_before_update BEFORE UPDATE ON node_contents FOR EACH ROW
BEGIN
	INSERT INTO node_content_revisions( 
		node_content_id, 
		user_id, 
		language_id, 
		content_name, 
		content_value,
		sort_order, 
		revision 
	) 
	VALUES ( 
		OLD.node_content_id, 
		COALESCE( OLD.editor_id, OLD.author_id, NULl ), 
		COALESCE( OLD.language_id, NULL ), 
		OLD.content_name, 
		OLD.content_value,
		OLD.sort_order,
		OLD.updated
	);
END;-- --

CREATE TRIGGER node_content_after_update AFTER UPDATE ON node_contents FOR EACH ROW
BEGIN
	-- Update rendered node content
	UPDATE nodes SET rendered = ( 
		SELECT GROUP_CONCAT( contents.rendered 
			ORDER BY contents.node_content_id ASC, 
			contents.sort_order ASC 
		) AS html 
		FROM node_contents contents 
			WHERE contents.node_id = NEW.node_id 
	) WHERE nodes.node_id = NEW.node_id;
	
	UPDATE node_meta SET authorship = '{ "authors" : [ ' || ( 
		SELECT GROUP_CONCAT( selection, ',' ) AS authors 
		FROM (
			SELECT ' {' || 
				'"user_id" 	: '	|| users.user_id		|| ', '		||
				'"username"	: "'	|| users.username		|| '", '	|| 
				'"title"	: "'	|| COALESCE( users.title, '' )	|| '", '	||
				'"content"	: "'	|| contents.content_name	|| '", '	||
				'"is_creator"	: '	|| (
					CASE
						WHEN contents.editor_id IS NULL THEN 1
						WHEN contents.editor_id = contents.author_id THEN 1
						ELSE 0
					END
				) || 
			' }' AS selection
			
			FROM node_contents contents
			LEFT JOIN users ON contents.author_id = users.user_id 
				OR contents.editor_id = users.user_id
			
			WHERE contents.node_id = NEW.node_id
			GROUP BY users.user_id
			ORDER BY contents.sort_order
		)
	) || ' ] }', updated = CURRENT_TIMESTAMP 
		WHERE node_meta.node_id = NEW.node_id;
END;-- --

CREATE TRIGGER node_content_date_after_update AFTER UPDATE ON node_contents FOR EACH ROW
WHEN OLD.updated = NEW.updated
BEGIN
	UPDATE node_contents SET updated = CURRENT_TIMESTAMP 
		WHERE node_content_id = NEW.node_content_id;
END;-- --



CREATE TABLE layouts (
	layout_id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL COLLATE NOCASE,
	html TEXT NOT NULL COLLATE NOCASE,
	
	CONSTRAINT uk_layout_name UNIQUE ( name )
);-- --

CREATE TABLE node_content_layouts (
	node_content_id INTEGER NOT NULL,
	layout_id INTEGER NOT NULL,
	
	-- view, create, edit etc...
	render_mode TEXT NOT NULL DEFAULT 'view',
	render_override TEXT,
	sort_order INTEGER NOT NULL DEFAULT 0,
	
	PRIMARY KEY ( node_content_id, layout_id ),
	FOREIGN KEY ( node_content_id ) 
		REFERENCES node_contents ( node_content_id ) ON DELETE CASCADE,
	FOREIGN KEY ( layout_id ) REFERENCES layouts ( layout_id ) ON DELETE CASCADE
);-- --
CREATE INDEX idx_content_layout_render ON node_content_layouts ( render_mode );-- --
CREATE INDEX idx_content_layout_sort ON node_content_layouts ( sort_order );-- --

CREATE VIEW node_content_layout_view AS SELECT 
	layouts.name AS layout_name,
	layouts.html AS html,
	content_layouts.render_override AS render_override,
	content_layouts.render_mode AS render_mode,
	content_layouts.sort_order AS sort_order
	
	FROM layouts
	LEFT JOIN node_content_layouts content_layouts ON 
		layouts.layout_id = content_layouts.layout_id;-- --


-- Categorization



-- Categorization
CREATE TABLE terms (
	term_id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL COLLATE NOCASE,
	slug TEXT NOT NULL COLLATE NOCASE
);-- --
CREATE UNIQUE INDEX idx_term_slug ON terms ( slug );-- --

CREATE TABLE taxonomy (
	taxo_id INTEGER PRIMARY KEY AUTOINCREMENT,
	term_id INTEGER NOT NULL,
	parent_id INTEGER,
	node_count INTEGER NOT NULL DEFAULT 0,
	setting_id INTEGER,
	settings_override TEXT COLLATE NOCASE,
	
	FOREIGN KEY ( term_id ) REFERENCES terms ( term_id ) ON DELETE CASCADE,
	FOREIGN KEY ( parent_id ) REFERENCES taxonomy ( taxo_id ) ON DELETE SET NULL,
	FOREIGN KEY ( setting_id ) REFERENCES config ( setting_id ) ON DELETE SET NULL
);-- --
CREATE INDEX idx_taxonomy_term ON taxonomy ( term_id );-- --
CREATE INDEX idx_taxonomy_parent ON taxonomy ( parent_id ) 
	WHERE parent_id IS NOT NULL;-- --
CREATE INDEX idx_taxonomy_settings ON taxonomy ( setting_id ) 
	WHERE setting_id IS NOT NULL;-- --

CREATE TABLE node_taxonomy (
	node_id INTEGER NOT NULL,
	taxo_id INTEGER NOT NULL,
	sort_order INTEGER NOT NULL DEFAULT 0,
	
	PRIMARY KEY ( node_id, taxo_id ),
	FOREIGN KEY ( node_id ) REFERENCES nodes ( node_id ) ON DELETE CASCADE,
	FOREIGN KEY ( taxo_id ) REFERENCES taxonomy ( taxo_id ) ON DELETE CASCADE
);-- --
CREATE INDEX idx_node_taxo_node_id ON node_taxonomy( node_id );-- --
CREATE INDEX idx_node_taxo_taxo_id ON node_taxonomy( taxo_id );-- --
CREATE INDEX idx_node_taxo_sort ON node_taxonomy ( sort_order );-- --

CREATE VIEW node_taxonomy_view AS SELECT 
	terms.term_id AS term_id,
	terms.name AS term_name,
	taxo.taxo_id AS taxo_id,
	taxo.parent_id AS parent_id,
	taxo.node_count AS node_count,
	taxo.setting_id AS setting_id,
	taxo.settings_override AS settings_override,
	nt.node_id AS node_id,
	nt.sort_order AS sort_order
	
	FROM taxonomy taxo
	JOIN terms ON taxo.term_id = terms.term_id
	LEFT JOIN node_taxonomy nt ON taxo.taxo_id = nt.taxo_id;-- --

-- Update node counts separately
CREATE TRIGGER node_taxonomy_count_insert AFTER INSERT ON node_taxonomy FOR EACH ROW 
BEGIN
	UPDATE taxonomy SET node_count = ( 
		SELECT COUNT node_id FROM node_taxonomy WHERE taxo_id = NEW.taxo_id
	) WHERE taxo_id = NEW.taxo_id;
END;-- --

CREATE TRIGGER node_taxonomy_count_delete BEFORE DELETE ON node_taxonomy FOR EACH ROW 
BEGIN
	UPDATE taxonomy SET node_count = ( 
		SELECT COUNT node_id FROM node_taxonomy WHERE taxo_id = OLD.taxo_id
	) - 1 WHERE taxo_id = OLD.taxo_id;
END;-- --



-- Uploaded media



CREATE TABLE resources (
	resource_id INTEGER PRIMARY KEY AUTOINCREMENT,
	author_id INTEGER,
	editor_id INTEGER,
	uuid TEXT,
	
	-- Download access label
	label TEXT COLLATE NOCASE,
	
	-- File path
	file_uri TEXT NOT NULL UNIQUE COLLATE NOCASE,
	content_length INTEGER NOT NULL DEFAULT 0,
	content_hash TEXT COLLATE NOCASE,
	mime_type TEXT NOT NULL DEFAULT 'application/octet-stream' COLLATE NOCASE,
	thumbnail_uri TEXT COLLATE NOCASE,
	created DATETIME DEFAULT CURRENT_TIMESTAMP,
	
	CONSTRAINT uk_resource_label UNIQUE ( label ),
	FOREIGN KEY ( author_id ) REFERENCES users ( user_id ) ON DELETE SET NULL,
	FOREIGN KEY ( editor_id ) REFERENCES users ( user_id ) ON DELETE SET NULL
);-- --
CREATE INDEX idx_resource_author ON resources ( author_id );-- --
CREATE INDEX idx_resource_editor ON resources ( editor_id )
	WHERE editor_id IS NOT NULL;-- --
CREATE INDEX idx_resource_uuid ON resources ( uuid )
	WHERE uuid IS NOT NULL;-- --
CREATE INDEX idx_resource_label ON resources( label );-- --
CREATE INDEX idx_resource_src ON resources( file_uri );-- --
CREATE INDEX idx_resource_hash ON resources( content_hash )
	WHERE content_hash IS NOT NULL;-- --
CREATE INDEX idx_resource_mime ON resources( mime_type );-- --
CREATE INDEX idx_resource_created ON resources( created );-- --

CREATE TABLE resource_revisions(
	resource_revision_id INTEGER PRIMARY KEY AUTOINCREMENT,
	resource_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	label TEXT NOT NULL COLLATE NOCASE,
	file_uri TEXT NOT NULL COLLATE NOCASE,
	content_length INTEGER NOT NULL DEFAULT 0,
	content_hash TEXT COLLATE NOCASE,
	mime_type TEXT NOT NULL COLLATE NOCASE,
	thumbnail_uri TEXT COLLATE NOCASE,
	revision DATETIME NOT NULL,
	
	FOREIGN KEY ( resource_id ) REFERENCES resources ( resource_id ) ON DELETE CASCADE
);-- --
CREATE INDEX idx_rev_revision_resource ON resource_revisions ( resource_id );-- --
CREATE INDEX idx_rev_revision_user ON resource_revisions( user_id );-- --
CREATE INDEX idx_rev_revision_revision ON resource_revisions ( revision DESC );-- --

CREATE TABLE resource_deleted(
	resource_id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL,
	uuid TEXT NOT NULL COLLATE NOCASE,
	label TEXT NOT NULL COLLATE NOCASE,
	file_uri TEXT NOT NULL COLLATE NOCASE,
	deleted DATETIME DEFAULT CURRENT_TIMESTAMP
);-- --

CREATE TRIGGER resource_after_insert AFTER INSERT ON resources FOR EACH ROW
BEGIN
	UPDATE resources SET uuid = ( SELECT id FROM uuid ) 
		WHERE resource_id = NEW.resource_id;
END;-- --

CREATE TRIGGER resource_label_after_insert AFTER INSERT ON resources FOR EACH ROW
WHEN NEW.label IS NULL
BEGIN
	UPDATE resources SET uuid = ( SELECT id FROM rnd ) 
		WHERE resource_id = NEW.resource_id;
END;-- --

CREATE TRIGGER resource_before_update BEFORE UPDATE ON resources FOR EACH ROW
WHEN OLD.uuid IS NOT NULL AND OLD.label IS NOT NULL
BEGIN 
	INSERT INTO resource_revisions( 
		resource_id, user_id, label, file_uri, content_length, 
			content_hash, mime_type, thumbnail_uri, revision ) 
	VALUES ( 
		OLD.resource_id, 
		COALESCE( OLD.editor_id, OLD.author_id ),
		OLD.label,  
		OLD.file_uri, 
		OLD.content_length,  
		OLD.content_hash,
		OLD.mime_type,
		OLD.thumbnail_uri,
		CURRENT_TIMESTAMP
	);
END;-- --

CREATE TRIGGER resource_before_delete BEFORE DELETE ON resources FOR EACH ROW
BEGIN
	INSERT INTO resource_deleted 
		( resource_id, user_id, uuid, label, file_uri ) 
	VALUES ( 
		OLD.resource_id, 
		COALESCE( OLD.editor_id, OLD.author_id ),
		OLD.uuid,
		OLD.label, 
		OLD.file_uri 
	);
END;-- --



-- Moderation



-- Content scoring
CREATE TABLE votes (
	vote_id INTEGER PRIMARY KEY AUTOINCREMENT, 
	node_id INTEGER NOT NULL,
	user_id INTEGER,
	
	-- Optionally weighted value
	score REAL NOT NULL,
	created DATETIME DEFAULT CURRENT_TIMESTAMP,
	
	FOREIGN KEY ( node_id ) REFERENCES nodes ( node_id ) ON DELETE CASCADE,
	FOREIGN KEY ( user_id ) REFERENCES users ( user_id ) ON DELETE SET NULL
);-- --
CREATE UNIQUE INDEX idx_vote_user_node ON votes ( node_id, user_id )
	WHERE user_id IS NOT NULL;-- --
CREATE INDEX idx_vote_node_id ON votes ( node_id );-- --
CREATE INDEX idx_vote_user_id ON votes ( user_id )
	WHERE user_id IS NOT NULL;-- --
CREATE INDEX idx_vote_created ON votes ( created );-- --
CREATE INDEX idx_vote_score ON votes ( score );-- --

-- Node vote ranking
CREATE TABLE node_ranking (
	node_id INTEGER PRIMARY KEY,
	rank_score REAL NOT NULL,
	total_votes INTEGER NOT NULL,
	
	FOREIGN KEY ( node_id ) REFERENCES nodes ( node_id ) ON DELETE CASCADE
);-- --
CREATE INDEX idx_rank_score ON node_ranking ( rank_score );-- --

-- Ranking algorithm (inspired by Hacker News)
CREATE TRIGGER node_vote_after_insert AFTER INSERT ON votes FOR EACH ROW
BEGIN
	INSERT INTO node_ranking ( node_id, rank_score, total_votes )
	VALUES (
		NEW.node_id, 
		(
			( 
				SELECT SUM( votes.score ) - 1 AS total FROM votes
					WHERE node_id = NEW.node_id 
			) / ( 
				SELECT POW( 
					( MAX( 
						strftime( '%s', 'now' ) - 
						strftime( '%s', nodes.created ), 1
					) / 3200 ) + 2, 1.8 
				) AS weight 
				FROM nodes WHERE node_id = NEW.node_id 
			) 
		), 
		( SELECT COUNT( node_id ) FROM votes WHERE node_id = NEW.node_id ) 
	)  
	ON CONFLICT ( node_id ) DO UPDATE SET 
	rank_score = (
		( 
			SELECT SUM( votes.score ) - 1 AS total FROM votes
				WHERE node_id = NEW.node_id 
		) / ( 
			SELECT POW( 
				( MAX( 
					strftime( '%s', 'now' ) - 
					strftime( '%s', nodes.created ), 1
				) / 3200 ) + 2, 1.8 
			) AS weight 
			FROM nodes
			WHERE node_id = NEW.node_id 
		)
	), total_votes = ( 
		SELECT COUNT( node_id ) FROM votes WHERE node_id = NEW.node_id 
	);
END;-- --

-- Content flags
CREATE TABLE reports (
	report_id INTEGER PRIMARY KEY AUTOINCREMENT,
	node_id INTEGER,
	user_id INTEGER,
	reason TEXT NOT NULL,
	created DATETIME DEFAULT CURRENT_TIMESTAMP,
	
	FOREIGN KEY ( node_id ) REFERENCES nodes ( node_id ) ON DELETE SET NULL,
	FOREIGN KEY ( user_id ) REFERENCES users ( user_id ) ON DELETE SET NULL
);-- --
CREATE INDEX idx_report_node_user ON reports( node_id, user_id ) 
	WHERE node_id IS NOT NULL AND user_id IS NOT NULL;-- --
CREATE INDEX idx_report_created ON reports ( created );



