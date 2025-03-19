
# Common database
package Perlite::Models::Database;

use strict;
use warnings;
use utf8;

use Carp;
use DBI;

use Perlite::Filter qw( trim unifySpaces labelName );
use Perlite::Reporting qw( cleanMsg );

sub new {
	my ( $class, $args )	= @_;
	if ( !defined $args->{config} ) {
		croak "Configuration required for Database";
	}
	
	# Default to SQLite
	$args->{db_type}	//= 'sqlite';
	
	my $self	= {
		config		=> $args->{config}
		dsn		=> $args->{dsn},
		username	=> $args->{username}	// '',
		password	=> $args->{password}	// '',
		db_file		=> $args->{db_file}	// '',
		db_type		=> lc( $args->{db_type}	// 'sqlite' )
	};
	bless	$self, $class;
	return	$self;
}

sub loadSQL {
	my ( $self, $sqlfile )	= @_;
	
	$sqlfile	=~ /^(.*)$/ and $sqlfile = $1;
	
	unless ( -f $sqlfile ) {
		$self->warnMsg( "Database ${sqlfile} file missing" );
		return 0;
	}
	
	# Prevent leaking storage file location
	my $raw	= '';
	
	open ( my $lines, '<:encoding(UTF-8)', $sqlfile ) or exit 1;
	while ( <$lines> ) {
		$raw .= $_;
	}
	
	close $lines;
	
	my @statements	= split( /-- --/, $raw );
	
	$self->{dbh}->begin_work;
	eval {
		for my $sql ( @statements ) {
			$sql		=~ s/^\s+|\s+$//g;
			next if $sql	=~ /^\s*$/;
			next if $sql	=~ /^--/;
			next if $sql	=~ /^\/*/;
			
			eval { $self->{dbh}->do($sql) };
			if ( $@ ) {
				$self->dieMsg( 
					"Error executing SQL statement: ${sql} | $@"
				);
			}
		}
		$self->{dbh}->commit;
	};
	
	if ( $@ ) {
		$self->{dbh}->rollback;
		$self->warnMsg( 
			"Error initializing database schema ${sqlfile}: $@ | " . 
				$self->{dbh}->errstr
		);
		return 0;
	}
	return 1;
}

# Preparation with SQLite PRAGMA settings
sub firstRun {
	my ( $self, $dbfile )	= @_;
	$self->{dbh}->do( 'PRAGMA encoding = "UTF-8";' );
	$self->{dbh}->do( 'PRAGMA page_size = "16384";' );
	$self->{dbh}->do( 'PRAGMA auto_vacuum = "2";' );
	$self->{dbh}->do( 'PRAGMA temp_store = "2";' );
	$self->{dbh}->do( 'PRAGMA secure_delete = "1";' );
	
	unless( $self-loadSQL( $dbfile . '.sql' ) ) {
		return 0;
	}
	
	# Instalation check
	eval { $self->{dbh}->do( 'PRAGMA integrity_check;' ) };
	if ( $@ ) {
		$self->warnMsg( "PRAGMA integrity_check failed: $@" );
		return 0;
	}
	
	eval { $self->{dbh}->do( 'PRAGMA foreign_key_check;' ) };
	if ( $@ ) {
		$self->warnMsg( "PRAGMA foreign_key_check failed: $@" );
		return 0;
	}
	
	return 1;
}

sub prepareSQLite {
	my ( $self, $dbh )	= @_;
	
	# Preemptive defense
	unless( eval { $dbh->do( 'PRAGMA quick_check;' ); 1 } ) {
		$self->dieMsg( 
			"PRAGMA quick_check failed: $@ | DBI Error" . 
				$self->{dbh}->errstr
		);
	}
	
	$dbh->do( 'PRAGMA trusted_schema = OFF;' );
	$dbh->do( 'PRAGMA cell_size_check = ON;' );
	
	# Prepare defaults if first run
	if ( defined( $self->{sqlite_first} ) && $self->{sqlite_first} ) {
		unless ( $self->firstRun( $self->{db_file} ) ) {
			$self->dieMsg( "First run initialization failed." );
		}
	}
	
	$dbh->do( 'PRAGMA journal_mode = WAL;' );
	$dbh->do( 'PRAGMA foreign_keys = ON;' );
}

# Initialize connection with presets
sub initConnection {
	my( $self, $dbh ) = @_;
	
	if ( $self->{db_type} eq 'sqlite' ) {
		my $df			= $self->{db_file};
		my ( $vol, $dir, $file) = splitpath( $df );
		
		# Attempt directory creation if it doesn't exist
		unless (-d $dir) {
			mkdir( $dir, 0750 ) or do {
				$self->dieMsg( 
					"Failed to create directory '$dir': $!"
				);
			};
		}
		
		# Need write access for SQLite
		unless ( $dir && -d $dir && -w $dir ) {
			$self->dieMsg( 
				"Cannot use SQLite. Directory '${dir}' " . 
				"does not exist or is not writable."
			);
		}
		
		$self->prepareSQLite( $dbh, $df );
	} else {
		my $timezone	= $self->{timezone} // 'UTC';
		$dbh->do( "SET SESSION sql_mode = 'TRADITIONAL';" );
		$dbh->do( "SET timezone = ${timezone};" );
	}
	
	return;				
}

# Create DBI connection
sub connect {
	my ( $self )	= @_;
	
	if ( $self->{db_type} eq 'sqlite' ) {
		
		unless( $self->{db_file} ) {
			$self->dieMsg( 
				"Cannot use SQLite. Database file not specified."
			);
		}
		my $df			= $self->{db_file};
		
		# Override DSN with filename for SQLite
		$self->{dsn}	= "DBI:SQLite:dbname=${df}";
		
		# Check if database path exists
		$self->{sqlite_first}	= ( ! -f $df );
	}
	
	$self->{dbh}	= 
	DBI->connect( 
		$self->{dsn}, 
		$self->{username}, 
		$self->{password}, 
		{
			AutoInactiveDestroy	=> 0,
			PrintError		=> 0,
			RaiseError		=> 1,
			Taint			=> 1,
			ChopBlanks		=> 1,
			Callbacks		=> {
				connected => sub { 
					eval { $self->initConnection( @_ ); };
					if ( $@ ) {
						$self->warnMsg( 
							"Error initializing connection: $@"
						);
					}
				}
			}
		} 
	);
	
	unless ( $self->{dbh} && $self->{dbh}->ping ) {
		$self->warnMsg( "Failed to establish database connection." );
		return 0;
	}
	
	return 1;
}

# Parent carp helper
sub warnMsg {
	my ( $self, $msg )	= @_;
	unless ( $self->{config}->{main}->debugState() ) {
		$msg = cleanMsg( $msg, (
			$self->{dsn},
			$self->{username},
			$self->{password},
			$self->{storage_dir}
		) );
	}
	$self->{config}->{main}->warnMsg( $msg, $is_debug );
}

# Parent croak helper
sub dieMsg {
	my ( $self, $msg )	= @_;
	unless ( $self->{config}->{main}->debugState() ) {
		$msg = cleanMsg( $msg, (
			$self->{dsn},
			$self->{username},
			$self->{password},
			$self->{storage_dir}
		) );
	}
	$self->{config}->{main}->dieMsg( $msg, $depth, $is_debug );
}

# Get last inserted row identifier
sub lastId {
	my ( $self )		= @_;
	return 0 unless $self->{dbh};
	my $id = $self->{dbh}->last_insert_id();
	
	return defined( $id ) ? $id : 0;
}

# Prepare and store SQL statement
sub statement {
	my ( $self, $sql ) = @_;
	
	$self->{stmcache}	//= {};
	
	# Unified hash key
	my $key	= lc( unifySpaces( $sql, '' ) );
	
	if ( exists( $self->{stmcache}->{$key} ) ) {
		return $self->{stmcache}->{$key};
	}
	
	$self->connect() unless $self->{dbh};
	
	eval {
		$self->{stmcache}->{$key} = 
			$self->{dbh}->prepare( $sql );
	};
	
	if ( $@ ) {
		$self->warnMsg( "Failed to prepare statement: ${sql} Error: $@" );
		return undef;
	}
	return $self->{stmcache}->{$key};
}

# Extract and parse field labels
sub columnNames {
	my ( $self, $params )	= @_;
	unless ( ref( $params ) eq 'HASH' ) {
		my $msg = 
		"Invalid argument. Expected a hash reference but got " . 
			ref( $params ) . ".";
		$self->dieMsg( $msg );
	}
	return map { labelName( $_ ) } keys %$params;
}

sub beginTransaction {
	my ( $self )	= @_;
	
	$self->{dbh}->begin_work or do {
		$self->dieMsg( 
			"Failed to start transaction: " . 
				$self->{dbh}->errstr
		);
	};
}

sub commitTransaction {
	my ( $self )	= @_;
	
	$self->{dbh}->begin_work or 
		$self->dieMsg( "Failed to commit: " . $self->{dbh}->errstr );
}

sub rollbackTransaction {
	my ( $self )	= @_;
	
	$self->{dbh}->begin_work or 
		$self->dieMsg( "Failed to rollback: " . $self->{dbh}->errstr );
}

# Create row
sub insertRow {
	my ( $self, $table, $params, $auto_fin ) = @_;
	
	unless ( ref( $params ) eq 'HASH' ) {
		$self->dieMsg( 
			"Invalid argument. Expected a hash reference but got " . 
			ref( $params ) . "."
		);
	}
	
	$table		= labelName( $table );
	$auto_fin	//= 0;
	my @columns	= $self->columnNames( $params );
	my @values	= values %$params;
	my $place	= join( ', ', ( '?' ) x @values );
	
	my $sql = 
	"INSERT INTO ${table} (" . join( ", ", @columns ) . 
		") VALUES ( ${place} );";
	
	my $sth = $self->statement( $sql );
	unless ( $sth ) {
		$self->warnMsg( "Unable to create SQL statement" );
		return 0;
	}
	
	eval { $sth->execute( @values ); };
	if ( $@ ) {
		$self->warnMsg( "Failed insert SQL: ${sql}" . $sth->errstr );
		return 0;
	}
	
	my $id = $self->lastId();
	if ( $auto_fin ) {
		$sth->finish;
	}
	return $id;
}

# Bulk record insertions
sub batchInsert {
	my ( $self, $table, $columns, $rows ) = @_;
	my $place	= join( ', ', map { '?' } @$columns );
	my $values	= join( ', ', map { "( $place )" } @$rows );
	
	my $sql = 
	"INSERT INTO $table (" . 
		join( ", ", map { labelName( $_ ) } @$columns ) . 
		") VALUES $values";
	
	my $sth = $self->statement( $sql );
	unless ( $sth ) {
		$self->warnMsg( "Unable to create SQL statement" );
		return 0;
	}
	
	$self->beginTransaction();
	eval{ $sth->execute( map { @$_ } @$rows ); };
	if ( $@ ) {
		$self->warnMsg( "Failed insert SQL: ${sql}" . $sth->errstr );
		$self->rollbackTransaction();
		return 0;
	}
	$self->commitTransaction();
	return 1;
}

# Modify record
sub updateRow {
	my ( $self, $table, $params, $conds, $auto_fin ) = @_;
	
	unless ( ref( $params ) eq 'HASH' && ref( $conds ) eq 'HASH' ) {
		$self->dieMsg( 
			"Invalid argument. Expected a hash reference but got non hash."
		);
	}
	
	$table		= labelName( $table );
	$auto_fin	//= 0;
	
	my $sets	= join( ', ', map{ "$_ = ? " } $self->columnNames( $params ) );
	my $wheres	= join( ', ', map{ "$_ = ?" } $self->columnNames( $conds ) );
	
	my $sql		= "UPDATE ${table} SET ${sets} WHERE ${wheres};";
	
	my $sth		= $self->statement( $sql );
	if ( $sth ) {
		my $rows = $sth->execute( values %$params, values %$conds );
		unless ( defined( $rows ) ) {
			$self->warnMsg( $sth->errstr || 'Error' );
			return 0;
		}
		if ( $auto_fin ) {
			$sth->finish;
		}
		return $rows;
	}
	return 0;
}

# Remove record
sub deleteRow {
	my ( $self, $table, $conds, $auto_fin ) = @_;
	
	unless ( ref( $conds ) eq 'HASH' ) {
		$self->dieMsg( 
			"Invalid argument. Expected a hash reference but got non hash: " . 
			ref( $conds ) . "."
		);
	}
	
	$table		= labelName( $table );
	$auto_fin	//= 0;
	my $wheres	= 
		join( ', ', map { "$_ = ?" } $self->columnNames( $conds ) );
	
	my $sql		= "DELETE FROM ${table} WHERE ${wheres};";
	
	my $sth		= $self->statement( $sql );
	unless ( $sth ) {
		$self->warnMsg( "Unable to create SQL statement" );
		return 0;
	}
	
	my $rows	= 0;
	eval {
		$rows = $sth->execute( values %$conds );
	};
	
	if ( $@ ) {
		$self->logError( $sth->errstr );
		return 0;
	}
	
	if ( $auto_fin ) {
		$sth->finish;
	}	
	unless ( $rows ) {
		$self->warnMsg( "No rows affected" );
		return 0;
	}
	return $rows;
}

# Record search
sub selectRows {
    my ( $self, $view, $conds, $page, $limit ) = @_;
	
	$conds	//= {};
	return 0 unless ref( $conds ) eq 'HASH';
	
	# Default values
	$page		//= 1;
	$limit		//= 10;		# Default to low limit
	my $offset = ( $page - 1 ) * $limit;
	
	$view = labelName( $view );
	
	my ( $wheres, @values ) = ( '', () );
	if ( %$conds ) {
		$wheres	= 
		'WHERE ' . 
			join( ' AND ', map{ "$_ = ?" } $self->columnNames( $conds ) );
		@values = values %$conds;
	}
	
	# Build SQL with pagination
	my $sql = "SELECT * FROM ${view} ${wheres} LIMIT ? OFFSET ?";
	push( @values, $limit, $offset );
	
	# Prepare and execute the statement
	my $sth = $self->statement($sql);
	unless ( $sth ) {
		$self->warnMsg( "Failed to prepare SQL: ${sql}" );
		return [];
	}
	
	eval { $sth->execute(@values); };
	if ( $@ ) {
		$self->warnMsg( "Failed to execute SQL: ${sql}, Error: $@" );
		return [];
	}
	
	# Fetch all rows
	my $rows = $sth->fetchall_arrayref( {} );
	$sth->finish;
	
	return $rows;
}

sub countRows {
	my ( $self, $view, $conds ) = @_;
	
	return 0 unless !ref( $view );
	
	$conds	//= {};
	return 0 unless ref( $conds ) eq 'HASH';
	
	$view = labelName($view);

	my ( $where, @values ) = ( '', () );
	if ( %$conds ) {
		$where	= 'WHERE ' . join(' AND ', map { "$_ = ?" } keys %$conds );
		@values	= values %$conds;
	}
	
	my $sql		= "SELECT COUNT(*) AS total FROM ${view} ${where}";
	my $sth		= $self->statement( $sql );
	eval { $sth->execute( @values ); };
	if ( $@ ) {
		$self->warnMsg( 
			"SQL Error counting rows from ${view}: " . 
			$sth->errstr || 'DB Statement'
		);
		return 0;
	}
	
	my $result = $sth->fetchrow_hashref();
	return $result->{total} || 0;
}

# Get the column labels from tables and views
sub getFields {
	my ( $self, $view ) = @_;
	
	$view	= labelName( $view );
	
	my $sql	= 
	$self->{db_type} eq 'sqlite' ? 
		"PRAGMA table_info( ${view} );" : 
		"DESCRIBE ${view};";
	
	my $sth		= $self->{dbh}->prepare( $sql );
	eval { $sth->execute(); };
	if ( $@ ) {
		$self->warnMsg( 
			"Field retrieval failed for view ${view}: " . 
			$sth->errstr
		);
		return ();
	}
	
	my $label	= $self->{db_type} eq 'sqlite' ? 'name' : 'Field';
	my @fields	= map { $_->{$label} } @{$sth->fetchall_arrayref({})};
	return @fields;
}

# Dynamic query builder with tables and views
sub selectDynamic {
	my ( $self, $view, $conds ) = @_;
	
	return {} unless !ref( $view );
	
	$conds	//= {};
	return {} unless ref( $conds ) eq 'HASH';
	
	# Fetch dynamic fields
	my @fields		= $self->getFields( $view );
	if ( !@fields ) {
		$self->logError( "No fields found for view: ${view}" );
		return {};
	}
	
	my $columns		= join( ", ", @fields ); 
	my ( $where, @values )	= ( '', () );
	
	if ( %$conds ) {
		$where	= 'WHERE ' . join( ' AND ', map { "$_ = ?" } keys %$conds );
		@values	= values %$conds;
	}
	
	my $sql	= "SELECT $columns FROM $view $where";
	my $sth	= $self->statement( $sql );
	
	eval { $sth->execute( @values ); };
	if ( $@ ) {
		$self->warnMsg( "Error in dynamic field select: " . $sth->errstr );
		return {};
	}
	return $sth->fetchall_arrayref( {} );
}

# Finish and 
sub dumpCache {
	my ( $self )	= @_;
	
	unless( defined( $self->{stmcache} ) && ref( $self->{stmcache} ) eq 'HASH' ) {
		return;
	}
	
	for my $key ( keys %{$self->{stmcache}} ) {
		eval { $self->{stmcache}->{$key}->finish(); };
		if ( $@ ) {
			$self->warnMsg(
				"Failed to finish statement ( key = ${key} ): $@"
			);
		}
	}
	delete( $self->{stmcache} );
}

# Disconnect and clear remaining database connections
sub dumpDbh {
	my ( $self )	= @_;
	
	return unless ref( $self->{dbh} )	&& 
		$self->{dbh}->can('ping')	&& 
		$self->{dbh}->ping;

	
	eval { 
		if ( $self->{dbh}->ping ) {
			$self->{dbh}->disconnect(); 
		}
	};
	if ( $@ ) {
		$self->warnMsg( "Failed to disconnect: $@" );
	}
}

# Free resources
sub cleanup {
	my( $self )	= @_;
	
	return if $self->{data_dumped};
	$self->{data_dumped}	= 1;
	
	$self->dumpCache();
	$self->dumpDbh();
	
	$self->{stmcache} = undef;
	$self->{dbh} = undef;
}

# Carry out cleanup
sub DESTROY {
	my ( $self )	= @_;
	return unless $self && ref( $self ) eq 'HASH';
	$self->cleanup();
	$self->SUPER::DESTROY() if $self->can( 'SUPER::DESTROY' );
}

1;

