#!/usr/bin/perl -wT

package Perlite;

# Basic security
use strict;
use warnings;


# Default encoding
use utf8;

# Standard modules in use
use MIME::Base64;
use File::Basename;
use File::Copy;
use File::Temp qw( tempfile tempdir );
use File::Spec::Functions qw( catfile canonpath file_name_is_absolute rel2abs );
use Encode;
use Digest::SHA qw( sha1_hex sha1_base64 sha256_hex sha384_hex sha384_base64 sha512_hex hmac_sha384 );
use Fcntl qw( SEEK_SET O_WRONLY O_EXCL O_RDWR O_CREAT );
use Errno qw( EEXIST );
use Time::HiRes ();
use Time::Piece;
use JSON qw( decode_json encode_json );

# Perl version
use 5.32.1;



# Default settings
use constant {
	# Core defaults
 	
	# Writable content location
	STORAGE_DIR		=> "storage",
	
	# Default configuration file name in storage and per-site
	CONFIG_FILE		=> "config.json",
	
	# Uploaded file subfolder in storage
	UPLOADS			=> "uploads",
	
	# Session storage fubfolder in storage
	SESSION_DIR		=> "sessions",
	
	# Username and password storage file name
	USER_FILE		=> "users.txt",
	
	# Username and given permissions
	ROLE_FILE		=> "roles.txt"
};

# Request methods and path handler map
our %path_map = (
	get	=> [	
		# Homepage
		{ path => "",				handler => "viewHome" },
		
		# Paginated index
		{ path => "page:page",			handler => "viewHome" },
		
		# Static file
		{ path => "static/:file",		handler => "viewStatic" },
		{ path => "static/:tree/:file",		handler => "viewStatic" },
		
		# Content creating/editing
		{ path => "new",			handler => "viewNewPost" },
		{ path => "edit/:tree",			handler => "viewEditPost" },
		
		# Access pages
		{ path => "login",			handler => "viewLogin" },
		{ path => "register",			handler => "viewRegister" },
		
		# Segment page or section
		{ path => ":tree",			handler => "viewHome" }
	],
	
	post	=> [
		{ path => "new",			handler => "doNewPost" },
		{ path => "edit",			handler => "doEditPost" },
		
		{ path => "login",			handler => "doLogin" },
		{ path => "register",			handler => "doRegister" }
	],
	
	head	=> [	
		# Homepage
		{ path => "",				handler => "viewHome" },
		{ path => "page:page",			handler => "viewHome" },
		
		{ path => "static/:file",		handler => "viewStatic" },
		{ path => "static/:tree/:file",		handler => "viewStatic" },
		
		{ path => "new",			handler => "viewNewPost" },
		{ path => "edit/:tree",			handler => "viewEditPost" },
		
		{ path => "login",			handler => "viewLogin" },
		{ path => "register",			handler => "viewRegister" },
		
		# Segment page or section
		{ path => ":tree",			handler => "viewHome" }
	]
);

# URL routing placeholders
our %markers = (
	":all"		=> "(?<all>.+)",
	':id'		=> "(?<id>[1-9][0-9]*)",
	':page'		=> "(?<page>[1-9][0-9]*)",
	':label'	=> "(?<label>[\\pL\\pN\\s_\\-]{1,30})",
	":nonce"	=> "(?<nonce>[a-z0-9]{10,30})",
	":token"	=> "(?<token>[a-z0-9\\+\\=\\-\\%]{10,255})",
	":meta"		=> "(?<meta>[a-z0-9\\+\\=\\-\\%]{7,255})",
	":tag"		=> "(?<tag>[\\pL\\pN\\s_\\,\\-]{1,30})",
	":tags"		=> "(?<tags>[\\pL\\pN\\s_\\,\\-]{1,255})",
	':year'		=> "(?<year>[2][0-9]{3})",
	':month'	=> "(?<month>[0-3][0-9]{1})",
	':day'		=> "(?<day>[0-9][0-9]{1})",
	':slug'		=> "(?<slug>[\\pL\\-\\d]+)",
	":tree"		=> "(?<tree>[\\pL\\/\\-_\\d\\s]{1,255})",
	":file"		=> "(?<file>[\\pL_\\-\\d\\.\\s]{1,120})"
);




# Utilities




# Formatted date time helper
sub timstamp {
	my @time	= localtime();
	
	return sprintf(
		"%04d%02d%02d_%02d%02d%02d",
		$time[5] + 1900,	# Year
		$time[4] + 1,		# Month (1-based)
		$time[3],		# Day
		$time[2],		# Hour
		$time[1],		# Minute
		$time[0]		# Second
	);
}

# Timestamp helper
sub dateRfc {
	my ( $stamp ) = @_;
	
	# Fallback to current time
	$stamp = time() unless defined $stamp;
	my $t = Time::Piece->strptime( "$stamp", '%s' );
	
	# RFC 2822
	return $t->strftime( '%a, %d %b %Y %H:%M:%S %z' );
}

# Find if text starts with given search needle
sub textStartsWith {
	my ( $text, $needle ) = @_;
	
	$needle	//= '';
	$text	//= '';
	
	my $nl	= length( $needle );
	return 0 if $nl > length($text);
	
	return substr( $text, 0, $nl ) eq $needle;
}

# Merge arrays and return unique items
sub mergeArrayUnique {
	my ( $items, $nitems ) = @_;
	
	# Check for array or return as-is
	unless ( ref( $items ) eq 'ARRAY' ) {
		die "Invalid parameter type for mergeArrayUnique\n";
	}
	
	if ( ref( $nitems ) eq 'ARRAY' && @{$nitems} ) {
		push ( @{$items}, @{$nitems} );
		
		# Filter duplicates
		my %dup;
		@{$items} = grep { !$dup{$_}++ } @{$items};
	}
	
	return $items;
}

# Filter number within min and max range, inclusive
sub intRange {
	my ( $val, $min, $max ) = @_;
	my $out = sprintf( "%d", "$val" );
 	
	return 
	( $out > $max ) ? $max : ( ( $out < $min ) ? $min : $out );
}

# Get raw __DATA__ content as text
sub getRawData {
	state $data;
	
	unless ( defined $data ) {
		local $/ = undef;
		$data = <DATA>;
	}
	
	return $data;
}

# Get allowed file extensions, content types, and file signatures ("magic numbers")
sub mimeList { 
	state %mime_list = ();
	if ( keys %mime_list ) {
		return %mime_list;
	}
	
	my $data = getRawData();
	
	# Mime data block
	while ( $data =~ /^(?<mime>--\s*MIME\s*data:\s*\n.*?\n--\s*End\s*mime\s*?data\s*)/msgi ) {
		my $find = $+{mime};
		trim( \$find );
		
		# Extension, type, and file signature(s)
		while ( $find =~ /^(?<ext>\S+)\s+(?<type>\S+)\s+(?<sig>.*?)\s*$/mg ) {
			my ( $ext, $type, $sig ) = ( $+{ext}, $+{type}, $+{sig} );
			if ( ! defined( $type ) ) {
				$type = 'application/octet-stream';
			}
			if ( ! defined( $sig ) ) {
				$sig = '';
			}
			my @sig = split( /\s+/, $sig );
			$mime_list{$ext} = { type => $type, sig => \@sig };
		}
	}
	
	return %mime_list;
}

# Append hash value by incrementing numerical key index
sub append {
	my ( $ref, $key, $msg ) = @_;
	
	# Nothing to append
	unless ( defined( $ref ) && ref( $ref ) eq 'HASH' ) {
		return;
	}
	
	if ( exists( $ref->{$key} ) ) {
		# Increment indexed hash value
		$ref->{$key}{ 
			scalar( keys %$ref->{$key} ) + 1 
		} = $msg;
		return;
	}
	$ref->{$key} = { 1 => $msg };
}

# Error and message report formatting helper
sub report {
	my ( $msg )	= @_;
	my ( $pkg, $fname, $line, $func ) = caller( 1 );
	
	$msg	||= 'Empty message';
	$msg	= unifySpaces( $msg );
	$fname	= filterPath( $fname );
	
	return 
	"${msg} ( Package: ${pkg}, File: ${fname}, " . 
		"Subroutine: ${func}, Line: ${line} )";
}

# Check if hash has an 'error' key set and is not 0
sub hasErrors {
	my ( $ref )	= @_;
	
	return 
	defined( $ref->{error} ) && ( 
		( $ref->{error} eq 'HASH' && keys %{ $ref->{error} } ) || 
		$ref->{error}
	) ? 1 : 0;
}




# Basic filtering




# Trim leading and trailing space 
sub trim {
	my ( $txt ) = @_;
	$$txt	=~ s/^\s+|\s+$//g;
}

# Usable text content
sub pacify {
	my ( $term ) = @_;
	$term	=~ s/
		^\s*				# Remove leading spaces
		| [^[:print:]\x00-\x1f\x7f]	# Unprintable characters
		| [\x{fdd0}-\x{fdef}]		# Invalid Unicode ranges
		| [\p{Cs}\p{Cf}\p{Cn}]		# Surrogate or unassigned code points
		| \s*$				# Trailing spaces
	//gx;
	return $term;
}

# Convert all spaces to single character
sub unifySpaces {
	my ( $text, $rpl, $br ) = @_;
	
	return '' unless defined( $text ) && $text ne '';
	
	$text	= pacify( $text );
	
	$br	//= 0;		# Preserve line breaks?
	$rpl	//= ' ';	# Replacement space, defaults to ' '
	
	if ( $br ) {
		$text	=~ s/[ \t\v\f]+/$rpl/;
	} else {
		$text	=~ s/[[:space:]]+/$rpl/;
	}
	
	trim( \$text );
	return $text;
}

# Decode URL encoded strings
sub utfDecode {
	my ( $term ) = @_;
	return '' if !defined( $term ) || $term eq '';
	
	$term	= pacify( $term );
	$term	=~ s/\.{2,}/\./g;
	$term	=~ s/\+/ /g;
	$term	=~ s/\%([\da-fA-F]{2})/chr(hex($1))/ge;
	
	if ( Encode::is_utf8( $term ) ) {
		$term	= Encode::decode_utf8( $term );
	}
	
	trim( \$term );
	return $term;
}

# Safely decode JSON to hash
sub jsonDecode {
	my ( $text )	= @_;
	return {} if !defined( $text ) || $text eq '';
	return {} if length( $text ) < 2;
	
	$text	= pacify( $text );
	if ( !Encode::is_utf8( $text ) ) {
		$text	= Encode::encode( 'UTF-8', $text );
	}
	
	my $out;
	eval {
		$out = decode_json( $text );
	};
	
	return {} if ( $@ );
	return $out;
}

# Length of given string
sub strsize {
	my ( $str ) = @_;
	
	$str = pacify( $str );
	if ( !Encode::is_utf8( $str ) ) {
		$str = Encode::encode( 'UTF-8', $str );
	}
	return length( $str );
}

# Limit the date given to a maximum value of today
sub verifyDate {
	my ( $stamp, $now ) = @_;
	
	# Current date ( defaults to today )
	$now	//= localtime->strftime('%Y-%m-%d');
	
	# Split stamp to components ( year, month, day )
	my ( $year, $month, $day ) = $stamp =~ m{^(\d{4})/(\d{2})/(\d{2})$};
	
	# Set checks
	return 0 unless defined( $year ) && defined( $month ) && defined( $day );
	
	# Range checks for year, month, day
	return 0 if  $year < 1900 ||  $month < 1 || $month > 12 || $day < 1 || $day > 31;
	
	# Current date ( year, month, day )
	my ( $year_, $month_, $day_ ) = $now =~ m{^(\d{4})-(\d{2})-(\d{2})$};
	
	# Given year greater than current year?
	if ( $year > $year_ ) {
		return 0;
	}
	
	# This year given?
	if ( $year == $year_ ) {
		
		# Greater than current month?
		if ( $month > $month_ ) {
			return 0;
		}
		
		# Greater than current day?
		if ( $month == $month_ && $day > $day_ ) {
			return 0;
		}
	}
	
	# Leap year?
	my $is_leap = (
		( $year % 4 == 0 && $year % 100 != 0 ) || 
		( $year % 400 == 0 ) 
	);
	
	# Days in February, adjusting for leap years
	my @dm	= ( 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 );
	$dm[1]	= 29 if $month == 2 && $is_leap;
	
	# Maximum day for given month
	return 0 if $day > $dm[$month - 1];
	
	return 1;
}

# Hooks and extensions
sub hook {
	my ( $data, $out )	= @_;
	state	%handlers;
	state	%output;
	
	$out		//= 0;
	
	# No event?
	return {} unless ( $data->{event} );
	
	# Hook event name
	my $name	= lc( unifySpaces( $data->{event}, '_' ) );
	
	# Register new handler?
	if ( $data->{handler} ) {
		# Safe handler name
		my $handler	= unifySpaces( $data->{handler}, '' );
		my $is_code	= ref( $handler ) eq 'CODE';
		
		# Check if subroutine exists and doesn't return undef
		return {} unless defined( &{$handler} ) || $is_code;
		
		# Limit hook to current package scope
		my $pkg		= __PACKAGE__;
		my $routine	= $is_code ? *{$handler}{NAME} : $handler;
		unless ( $routine =~ /^${pkg}::/ ) {
			return {};
		}
		
		# Initialize event
		$handlers{$name} //= [];
		
		push( @{$handlers{$name}}, $handler );
		return {};
	}
	
	# Check event registry
	return {} unless exists $handlers{$name};
	
	# Get output only without executing event
	if ( $out ) {
		return $output{$name} // {};
	}
	
	# Check params integrity
	my $params	= 
	( defined( $data->{params} ) && ref( $data->{params} ) eq 'HASH' ) ? 
		%{$data->{params}} : {};
	
	# Trigger event
	for my $handler ( @{$handlers{$name}} ) {
		
		# Execute handlers in order and store in output
		$output{$name} = 
		&{$handler}( $name, $output{$name} // {}, $params );
	}
}




# IO Helpers




# Convert to a valid file or directory path
sub filterPath {
	my ( $path, $ns ) = @_;
	
	# Define reserved characters
	state @reserved	= qw( : * ? " < > | ; );
	
	# New filter characters?
	if ( $ns ) {
		@reserved = @{ mergeArrayUnique( \@reserved, $ns ) };
	}
	
	my $chars	= join( '', map { quotemeta( $_ ) } @reserved );
	$path		=~ s/[$chars]//g;
	$path		= unifySpaces( $path );
	
	# Convert relative path to absolute path if needed
	if ( !file_name_is_absolute( $path ) && $path =~ /\S/ ) {
		$path = rel2abs( $path );
	}
	
	# Canonical filter
	return canonpath( $path );
}


sub filterFileName {
	my ( $fname, $ns ) = @_;
	state @reserved = 
	qw(
		CON PRN AUX NUL COM1 COM2 COM3 COM4 COM5 COM6 COM7 COM8 COM9 \
		LPT1 LPT2 LPT3 LPT4 LPT5 LPT6 LPT7 LPT8 LPT9
	);
	
	# Append to reserved list?
	if ( $ns ) {
		@reserved = @{ mergeArrayUnique( \@reserved, $ns ) };
	}
	
	# Basic filtering
	$fname = filterPath( $fname );
	$fname =~ s/[\/\\]/_/g;
	$fname =~ s/^./_/;
	
	# Reserved filtering
	for my $res ( @reserved ) {
		if ( lc( $fname ) eq lc( $res ) ) {
			$fname	= "_$fname";
			last;
		}
	}
	
	# Maximum file name length
	my $fnlimit	= setting( 'file_name_limit', 'int', 255 );
	return substr( $fname, 0, $fnlimit ); 
}

# Relative storage directory
sub storage {
	my ( $path ) = @_;
	state $dir;
	
	unless ( defined $dir ) {
		$dir = pacify( STORAGE_DIR );
		if ( $dir eq '' ) {
			die "Storage directory is empty";
		}
		
		$dir = filterPath( $dir );
		unless ( -d $dir && -r $dir && -w $dir ) {
			die "Storage directory is not accessible";
		}
	}
	
	$path	= pacify( $path );
	
	# Remove leading slashes and spaces, if any, and double dots
	$path	=~ s/^[\s\/]+//;
	$path	=~ s/\.{2,}/\./g;
	
	return catfile( $dir, $path );
}

# Rename duplicate files until the filename doesn't conflict
sub dupRename {
	my ( $dir, $fname, $path ) = @_;
	
	my ( $base, $ext ) = fileparse( $fname, qr/\.[^.]*/ );
	my $i	= 1;
	
	# Keep modifying until file name doesn't exist
	while ( -e $path ) {
		$path	= catfile( $dir, "${base} ($i)$ext" );
                $i++;
	}
	
	return $path;
}

# File lock/unlock helper
sub fileLock {
	my ( $fname, $ltype ) = @_;
	
	$fname	= unifySpaces( $fname );
	unless ( $fname =~ /^(.*)$/ ) {
		# File name failure
		return 0;
	}
	$fname	= canonpath( $1 );
	
	# Lockfile name
	my $fl	= "$fname.lock___";
	
	# Default to removing lock
	$ltype	//= 0;
	
	# Remove lock
	if ( $ltype == 0 ) {
		# No lock
		if ( ! -f $fl ) {
			return 1;
		}
		unlink( $fl ) or return 0;
		return 1; # Lock removed
	}
	
	my $tries	= setting( 'lock_tries', 'int', 4 );
	while ( not sysopen ( my $fh, $fl, O_WRONLY | O_EXCL | O_CREAT ) ) {
		if ( $tries == 0 ) {
			return 0;
		}
		
		# Couldn't open lock even without lock file existing?
		if ( $! && $! != EEXIST ) {
			return 0; # Lock failed
		}
		
		$tries--;
		sleep 0.1;
	}
	
	# Lock acquired
	return 1;
}

# Search path(s) for files by given pattern
sub fileList {
	my ( $dir, $fref, $pattern ) = @_;
	unless ( -d $dir ) {
		return;
	}
	
	$pattern	= 
	quotemeta( $pattern ) unless ref( $pattern ) eq 'Regexp';
	
	find( sub {
		no warnings 'once';
		push( @{$fref}, $File::Find::name ) if ( $_ =~ $pattern );
	}, $dir );
}

# Get file contents
sub fileRead {
	my ( $file ) = @_;
	my $out	= '';
	
	$file	=~ /^(.*)$/ and $file = $1;
	
	open ( my $lines, '<:encoding(UTF-8)', $file ) or exit 1;
	while ( <$lines> ) {
		$out .= $_;
	}
	
	close ( $lines );
	return $out;
}

# Write contents to file
sub fileWrite {
	my ( $file, $data ) = @_;
	
	$file	=~ /^(.*)$/ and $file = $1;
	
	open ( my $lines, '>:encoding(UTF-8)', $file ) or exit 1;
	print $lines $data;
	
	close ( $lines );
}

# Search directory for words
sub searchFiles {
	my ( $dir, $words, $ext, $page, $limit )	= @_;
	
	unless ( -d $dir ) {
		return ();
	}
	
	my $pattern	= join( '|', map { quotemeta } @$ext );
	$pattern	= qr/\Q$pattern\E$/i;
	
	$limit		//= 10;
	$page		//= 1;
	
	my $offset	= $limit * $page - 1;
	
	my @files;
	fileList( $dir, \@files, $pattern );
	
	@files = sort( @files );
	
	my @items	= ();
	my $count	= 0;
	my $found	= 0;
	
	foreach my $fpath ( @files ) {
		if ( @items >= $limit ) {
			last;
		}
		
		open ( my $fh, '<:encoding(UTF-8)', $fpath ) or next;
		
		# Line-by line search
		while ( my $line = <$fh> ) {
			# Iterate through search terms
			foreach my $word ( @$words ) {
				if ( $line =~ /\b\Q$word\E\b/i) {
					$found = 1;
					last;
				}
			}
			
			# Skip rest of the lines
			if ( $found ) {
				last;
			}
		}
		
		close( $fh );
		
		if ( $found ) {
			$count++;
			if ( $count > $offset ) {
				push( @items, $fpath );
			}
			$found	= 0;
		}
	}
	
	return @items;
}

# Save text to file
sub fileSave {
	my ( $path, $data ) = @_;
	
	$path = storage( $path );
	
	# If file exists, create a backup
	if ( -e $path ) {
		my $bkp	= $path . '_backup_' . timestamp();
		copy( $path, $bkp ) or die "Failed creating backup";
	}
	
	fileWrite( $path, $data );
}





# Configuration settings




# Override JSON encoded string configuration
sub setConfig {
	my ( $settings, $override )	= @_;
	if ( !defined( $override ) || $override eq '' ) {
		return $settings;
	}
	
	# Configuration override
	my %oconfig	= jsonDecode( $override );
	return $settings if !keys %oconfig;
	
	%$settings	= ( %$settings, %oconfig );
	return $settings;
}

# Load configuration by realm or core
sub config {
	my ( $realm, $override )	= @_;
	$realm			//= '';
	$override		//= '';
	
	state %settings		= {};
	state %rsettings	= {};
	
	if ( $realm eq '' ) {
		return \%settings if keys %settings;
	} else {
		return \%rsettings if keys %rsettings;
	}
	
	# Default config
	my $conf		= fileRead( storage( CONFIG_FILE ) );
	if ( $conf ne '' ) {
		%settings	= jsonDecode( $conf );
	}
	
	# Override base settings for this session, if needed
	if ( $override ne '' ) {
		%settings	= setConfig( \%settings, $override );
	}
	
	# Realm settings default to base settings
	%rsettings	= %settings;
	
	# Find realm specific config, if given, and merge to core
	if ( $realm ne '' ) {
		my $rconf	=  fileRead( catfile( $realm, CONFIG_FILE ) );
		if ( $rconf ne '' ) {
			my %nconfig	= jsonDecode( $rconf );
			if ( keys %nconfig ) {
				%rsettings	= ( %rsettings, %nconfig );
			}
		}
		
		# Override realm settings for this session
		if ( $override ne '' ) {
			%rsettings	= setConfig( \%rsettings, $override );
		}
		
		return \%rsettings;
	}
	
	return \%settings;
}

# Fitered configuration setting by realm or core
sub setting {
	my ( $label, $vtype, $default, $realm )	= @_;
	
	$vtype		= lc( $vtype // 'string' );
	
	my $config	= config( $realm // '' );
	my $val		= $config->{$label} // '';
	$default	//= '';
	
	if ( $val eq '' ) {
		return $default;
	}
	
	for ( $vtype ) {
		/int/ and do {
			return ( looks_like_number( $val ) && $val == int( $val ) ) ? 
			$val : $default;
		};
		
		/string/ and do {
			return !ref( $val ) ? $val : $default;
		};
		
		/hash/ and do {
			return ( ref( $val ) eq 'HASH' ) ? $val : $default;
		};
	}
	
	return $default;
}





# Request 





# Raw request headers
sub requestHeaders {
	state %headers	= ();
	
	# Relevant header names
	state @prefix	= 
	qw/CONTENT CONTEXT HTTP QUERY REMOTE REQUEST SCRIPT SERVER/;
	
	if ( keys %headers ) {
		return %headers;
	}
	
	for my $var ( sort( keys %ENV ) ) {
		foreach my $prefix ( @prefix ) {
			if ( $var =~ /^\Q$prefix\E/ ) {
				$headers{lc( $var )} = $ENV{$var};
				last;
			}
		}
	}
	
	return %headers;
}

# Current host or server name/domain/ip address
sub siteRealm {
	my $realm	= lc( $ENV{SERVER_NAME} // '' );
	$realm		=~ s/[^a-zA-Z0-9\.\-]//g;
	
	# End early on empty realm
	sendBadRequest() if ( $realm eq '' );
	
	# Check for reqested realm, if it exists
	my $dir = storage( catfile( 'sites', $realm ) );
	if ( ! -d $dir ) {
		sendBadRequest();
	}
	
	return $realm;
}

# Guess if current request is secure
sub isSecure {
	# Request protocol scheme HTTP/HTTPS etc..
	my $scheme	= lc( $ENV{REQUEST_SCHEME} // 'http' );
	
	# Forwarded protocol, if set
	my $frd		= lc(
		$ENV{HTTP_X_FORWARDED_PROTO}	//
		$ENV{HTTP_X_FORWARDED_PROTOCOL}	//
		$ENV{HTTP_X_URL_SCHEME}		// 'http'
	);
	
	return ( $scheme eq 'https' || $frd  =~ /https/ );
}

# HTTP Client request
sub getRequest {
	
	state %request;
	if ( keys %request ) {
		return %request;
	}
	
	%request = (
		# Server/website name
		'realm'		=> siteRealm(),
	
		# Requested path
		'url'		=> $ENV{REQUEST_URI}		//= '/',
		
		# Client request method
		'verb'		=> lc( $ENV{REQUEST_METHOD}	//= '' ),
		
		# TLS connection status
		'secure'	=> isSecure(),
		
		# Request query string
		'query'		=> $ENV{QUERY_STRING}		//= ''
	);
	
	return %request;
}

# Accept header content types and their given priority
sub getAcceptMedia {
	state %types;
	if ( keys %types ) {
		return %types;
	}
	
	my $header		= lc( $ENV{ACCEPT} // '' );
	if ( $header eq '' ) {
		return \%types;
	}
	
	my @content_types	= split( /\s*,\s*/, $header );
	
	foreach my $type ( @content_types ) {
		
		if ( $type =~ /^([^;]+)(?:\s*;\s*q\s*=\s*(\d(\.\d+)?))?$/ ) {
			my $content		= $1;
			$content		=~ s/[^a-z0-9\/\+\-]+//g;
			if ( $content eq '' ) {
				next;
			}
			
			my $q_value		= defined( $2 ) ? $2 : 1;
			$q_value		= 1 if $q_value > 1;
			$q_value		= 0 if $q_value < 0;
			
			$types{lc($content)}	= $q_value;
		}
	}
	
	return \%types;
}

# Get requested file range, return range error if range was invalid
sub requestRanges {
	my $fr = $ENV{HTTP_RANGE} //= '';
	return () unless $fr;
	
	# Range is too long
	if ( length( $fr ) > 100 ) {
		sendRangeError();
	}
	
	my @ranges;
	
	# Check range header
	my $pattern	= qr/
		bytes\s*=\s*				# Byte range heading
		(?<ranges>(?:\d+-\d+(?:,\s*\d+-\d+)*))	# Comma delimited ranges
	/x;
	
	# Check range header
	while ( $fr =~ m/$pattern/g ) {
		
		my $capture = $+{ranges};
		while ( $capture =~ /(?<range>\d+-(?:\d+)?)/g ) {
			my ( $start, $end ) = split /-/, $+{range};
			
			# End can't be greater than start
			if ( defined( $end ) && $start >= $end ) {
				sendRangeError();
			}
			
			# Check overlapping ranges
			foreach my $check ( @ranges ) {
				my ( $cs, $ce ) = @{$check};
				
				# New range crosses prior start-end ranges?
				if ( 
					$start <= $ce	&& 
					( defined( $end ) ? $end >= $cs : 1 )
				) {
					sendRangeError();
				}
			}
			
			push( @ranges, [$start, $end] );
		}
	}
	
	# Invalid range syntax?
	if ( !@ranges ) {
		sendRangeError();
	}
	
	# Send filtered file ranges
	return \@ranges;
}

# URI / URL
sub urlPath {
	my ( $uri ) = @_;
	
	$uri =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
	return $uri;	
}

# Temporary storage for incoming form data
sub formDataStream {
	my ( $clen ) = @_;
	
	my $bytes		= 0;
	my $chunk;
	my %err;
	
	my ( $tfh, $tfn )	= 
	tempfile(
		DIR	=> storage( UPLOADS ), 
		SUFFIX	=> '.tmp' 
	);
	
	unless ( $tfh ) {
		append( 
			\%err, 'formDataStream', 
			report( "Failed to create a temp file for form data" ) 
		);
		return { error => \%err };
	}
	
	local $| = 1;	# Temporarily disable output buffering
	
	# Streaming chunk size
	my $chunk_size	= setting( 'chunk_size', 'int', 65536 );
	
	while ( $bytes < $clen ) {
		my $remaining	= $clen - $bytes;	# Default chunk size to remaining bytes
		my $read_size	= $remaining > $chunk_size ? $chunk_size : $remaining;
		
		# Reset chunk
		$chunk		= '';
		my $read	= sysread( STDIN, $chunk, $read_size );
		
		if ( !defined( $read ) || $read == 0 ) {
			append( 
				\%err, 'formDataStream', 
				report( "Error reading input data" ) 
			);
			
			close( $tfh );
			unlink( $tfh );
			return { error => \%err };
		}
		
		print $tfh $chunk or do {
			append( 
				\%err, 'formDataStream', 
				report( "Error writing to form data temporary file: $!" ) 
			);
			
			close( $tfh );
			unlink( $tfh );
			return { error => \%err };
		};
		$bytes	+= $read;
	}
	
	# Recheck boundary size
	if ( $bytes != $clen ) {
		append( 
			\%err, 'formDataStream', 
			report( "Boundary overflow: expected $clen, got $bytes" ) 
		);
		
		close( $tfh );
		unlink( $tfh );
		return { error => \%err };
	}

	# Reset seek to beginning of file
	seek( $tfh, 0, 0 ) or do {
		append( 
			\%err, 'formDataStream', 
			report( "Failed to reset seek position to beginning of temp file" ) 
		);
		
		close( $tfh );
		unlink( $tfh );
		return { error => \%err };
	};
	
	return { name => $tfn, stream => $tfh };
}

# Process form data boundary segments
sub formDataSegment {
	my ( $buffer, $boundary, $fields, $uploads ) = @_;
	
	# Split the segment by boundary
	my @segs = split(/--\Q$boundary\E(?!-)/, $buffer );
	shift @segs if @segs > 0;
	pop @segs if @segs && $segs[-1] eq '';
	
	my $pattern	= 
	qr/
		form-data;\s?					# Marker
		name="([^"]+)"(?:;\s?filename="([^"]+)")?	# Labeled names
	/ix;

	# File uploads and form handling temp file directory
	my $dir		= storage( UPLOADS );
	my %err;
	
	foreach my $part ( @segs ) {
		
		# Break by new lines
		my ( $headers, $content ) = split(/\r?\n\r?\n/, $part, 2 ) or do  {
			append( 
				\%err, 'formDataSegment', 
				report( "Header and content split failed" ) 
			);
			return { error => \%err };
		};
		
		if ( 
			!defined( $headers )	|| 
			!defined( $content )	|| 
			$content =~ /^\s*$/ 
		) {
			append( 
				\%err, 'formDataSegment', 
				report( "Malformed multipart data, missing headers or content" ) 
			);
			return { error => \%err };
		}
		
		# Parse headers
		my %parts;
		foreach my $line ( split( /\r?\n/, $headers ) ) {
			next unless $line;
			next unless $line =~ /^(\S+):\s*(.*)/;
			
			my ( $key, $value ) = ( lc( unifySpaces( $1, '-' ) ), $2 );
			trim( \$value );
			
			if ( exists( $parts{$key} ) ) {
				if ( ref( $parts{$key} ) ne 'ARRAY' ) {
   					# Convert to array
					$parts{$key} = [$parts{$key}, $value];
				} else {
					push( @{$parts{$key}}, $value );
				}
			} else {
				$parts{$key} = $value;
			}
		}
		
		# File uploads
		if ( $parts{'content-disposition'} =~ /$pattern/ ) {
			my ( $name, $fname )	= ( $1, $2 );
			
			if ( !defined( $fname ) || !defined( $name ) ) {
				next;
			}
			
			my $ptype	= 
			$parts{'content-type'} // 'application/octet-stream';
			
			$fname		= filterFileName( $fname );
			$name		= filterFileName( $name );
			
			my ( $tfh, $tname ) = tempfile();
			
			# Temp file failed?
			unless ( $tfh ) {
				append( 
					\%err, 'formDataSegment', 
					report( "Temp file creation error for file upload ${name} at ${tname}" ) 
				);
				return { error => \%err };
			}
			
			print $tfh $content or do {
				append( 
					\%err, 'formDataSegment', 
					report( "Error writing to form data temporary file: $!" ) 
				);
				
				close( $tfh );
				unlink( $tfh );
				return { error => \%err };
			};
			
			close( $tfh ) or do {
				append( 
					\%err, 'formDataSegment', 
					report( "Error closing temporary file: ${tfn}" ) 
				);
				return { error => \%err };
			};
			
			# Special case if file was moved/deleted mid-operation
			unless ( -e $tfn ) {
				append( 
					\%err, 'formDataSegment', 
					report( "Temporary file was moved, deleted, or quarantined: ${tfn}" ) 
				);
				# Nothing left to close or delete
				return { error => \%err };
			}
			
			my $fpath	= catfile( $dir, $fname );
			
			# Find conflict-free file name
			$fpath		= dupRename( $dir, $fname, $fpath );
			
			move( $tname, $fpath ) or do {
				append( 
					\%err, 'formDataSegment', 
					report( "Error moving temp upload file $!" ) 
				);
				unlink( $tname );
				
				# Don't continue until moving issue is resolved
				return { error => \%err };
			};
			
			push( @{$uploads}, {
				name		=> $name,
				filename	=> $fname,
				path		=> $fpath,
				content_type	=> $ptype
			} );
			
			# Done with upload file
			next;
		}
		
		# Ordinary form data
		my $name = $parts{'name'};
		$fields->{$name} = $content;
	}
	
	if ( keys %err ) {
		return { error => \%err };
	}
	
	return {};
}

# Sent binary data
sub formData {
	state %data = ();
	
	if ( keys %data ) {
		return \%data;
	}
	
	my %err;
	my %request_headers	= requestHeaders();
	my $clen		= $request_headers{'content_length'} // 0;
	unless ( $clen && $clen =~ /^\d+$/ ) {
		append( \%err, 'formData', report( "Invalid content length" ) );
		
		return { fields => [], files => [], error => \%err };
	}
	
	my $ctype		= $request_headers{'content_type'} // '';
	
	# Check multipart boundary
	my $boundary;
	if ( $ctype =~ /^multipart\/form-data;.*boundary=(?:"([^"]+)"|([^;]+))/ ) {
		$boundary = $1 || $2;
		$boundary = unifySpaces( $boundary );
	} else {
		append( \%err, 'formData', report( "No multipart boundary found" ) );
		
		return { fields => [], files => [], error => \%err };
	}
	
	my %state		= formDataStream( $clen );
	if ( hasErrors( $state ) ) {
		%err = %{$state->{error}};
		# Merge stream errors
		append( 
			\%err, 'formData', 
			report( "Error saving form data stream" )
		);
		
		return { fields => [], files => [], error => \%err };
	}
	
	my %fields = ();
	my @uploads = [];
	
	# Process the file content in chunks
	my $buffer = '';
	while ( my $line = <$state->{stream}> ) {
		$buffer .= $line;

		# Once a boundary is reached, process the segment
		if ( $buffer =~ /--\Q$boundary\E(?!-)/ ) {
			my %segment = formDataSegment( $buffer, $boundary, \%fields, \@uploads );
			if ( hasErrors( $segment ) ) {
				%err = %{$segment->{error}};
				append( 
					\%err, 'formData', 
					report( "Form data stream failed" )
				);
				
				# Cleanup form data stream
				close( $state->{stream} );
				unlink( $state->{name} );
				return { fields => [], files => [], error => \%err };
			}
			
			# Reset
			$buffer = '';  
		}
	}
	
	# Cleanup form data stream
	close( $state->{stream} );
	unlink( $state->{name} );
	
	$data{'fields'}	= \%fields;
	$data{'files'}	= \@uploads;
	
	return \%data;
}

# Verify sent form data with nonce and CAPTCHA
sub validateCaptcha {
	my ( $snonce )	= @_;
	
	my %data	= formData();
	unless ( hasErrors( $data ) ) {
		return 0;
	}
	
	my %fields	= %data->{fields} // {};
	unless ( keys %fields ) {
		return 0;
	}
	
	if ( 
		!defined( $fields{nonce} )	|| 
		!defined( $fields{cnonce} )	|| 
		!defined( $fields{captcha} )
	) {
		return 0;
	}
	
	my ( $nonce, $cnonce, $captcha ) = ( 
		$fields{nonce}, $fields{cnonce}, $fields{captcha} 
	);

	# Filter everything
	$nonce		= unifySpaces( $nonce );
	$cnonce		= unifySpaces( $cnonce );
	$captcha	= unifySpaces( $captcha );
	
	if ( $snonce ne $nonce ) {
		return 0;
	}
	
	# Match fixed sizes
	my ( $csize, $nsize ) = (
		# CAPTCHA field character length
		setting( 'captcha_size', 'int', 8 ),
		
		# Form validation nonce length
		setting( 'nonce_size', 'int', 64 )
	);
	
	if  ( 
		$csize	!= length( $captcha )	|| 
		$nsize	!= length( $cnonce ) 
	) {
		return 0;
	}
	
	# Create a hash with nonce and cnonce and widen character set
	my $chk	= encode_base64( sha256_hex( $nonce . $cnonce ), '' );
	
	# Remove confusing characters (must match client-side code)
	$chk	=~ s/[0oO1liNzZ2m3=\/]//g;
	
	# Limit to CAPTCHA length (must match client-side code)
	if ( lc( substr( $chk, 0, $csize ) ) eq lc( $captcha ) ) {
		return 1;
	}
	
	# Default to fail
	return 0;
}




# Cookie handling




# Get all cookie data from request
sub getCookies {
	state %sent;
	
	return %sent if keys %sent;
	
	my @items	= split( /;/, $ENV{'HTTP_COOKIE'} // '' );
	foreach my $item ( @items ) {
		my ( $k, $v )	= split( /=/, $item, 2 );
		
		# Clean prefixes, if any
		$k		=~ s/^__(Host|Secure)\-//gi;
		$sent{pacify( $k )} = pacify( $v );
	}
	
	return %sent;
}

# Get specific cookie key value, if it exists
sub getCookieData {
	my ( $key ) = @_;
	my %cookies = getCookies();
	
	return $cookies{$key} //= '';
}

# Set host/secure limiting prefix
sub cookiePrefix {
	my %request	= getRequest();
	
	# Base domain path
	my $cpath	= setting( 'cookie_path', 'string', '/' );
	return 
	( $cpath eq '/' && $request{'secure'} ) ? 
		'__Host-' : ( $request{'secure'} ? '__Secure-' : '' );
}

# Set cookie values to user
sub cookieHeader {
	my ( $data, $ttl ) = @_;
	
	my %request	= getRequest();
	my $prefix	= cookiePrefix();
	my $cpath	= setting( 'cookie_path', 'string', '/' );
	my @values	= ( 
		$prefix . $data,
		'Path=' . $cpath,
		'SameSite=Strict',
		'HttpOnly',
	);
	
	# Cookies without explicit expiration left up to the browser
	if ( $ttl != 0 ) {
		push ( @values, 'Max-Age=' . $ttl );
		push ( @values, 'Expires=' . gmtime( $ttl + time() ) .' GMT' );
	}
	
	if ( $request{'secure'} ) {
		push ( @values, 'Secure' );
	} 
	
	if ( $prefix eq '__Secure' || $prefix eq '' ) {
		push ( @values, 'Domain=' . $request{'realm'} );
	}
	
	my $cookie	= join( '; ', @values );
	print "Set-Cookie: $cookie\n";
}

# Set a cookie with default parameters
sub setCookie {
	my ( $name, $value, $ttl ) = @_;
	
	# Base expiration
	$ttl	//= setting( 'cookie_exp', 'int', 604800 );
	if ( $ttl < 0 ) {
		$ttl = 0;
	}
	
	cookieHeader( "$name=$value", $ttl );
}

# Erease already set cookie by name
sub deleteCookie {
	my ( $name ) = @_;
	
	cookieHeader( "$name=", 0 );
}




# Session management




# Strip any non-cookie ID data
sub sessionCleanID {
	my ( $id ) = @_;
	$id		= pacify( $id );
	$id		=~ /^([a-zA-Z0-9]{20,255})$/;
	
	return $id;
}

# Generate or return session ID
sub sessionID {
	my ( $sent ) = @_;
	state $id = '';
	
	$sent //= '';
	if ( $sent ne '' ) {
		$id = sessionCleanID( $sent ); 
	}
	
	if ( $id eq '' ) {
		# New pseudorandom ID
		$id = sha256_hex( 
			Time::HiRes::time() . rand( 2**32 ) 
		);
	}
	
	return $id;
}

# Send session cookie
sub sessionSend {
	# Time before session cookie expires
	my $sexp = setting( 'session_exp', 'int', 1800 );
	setCookie( 'session', sessionID(), $sexp );
}

# Create a new session with blank data
sub sessionNew {
	sessionID( '' );
	sessionSend();
}

# Get or store session data to scoped hash
sub sessionWrite {
	my ( $key, $value ) = @_;
	
	# Session stroage data
	state %session_data = ();
	
	if ( $key ) {
		$session_data{$key} = $value;
		return;
	}
	
	return %session_data;
}

# Read cookie data from database, given the ID
sub sessionRead {
	my ( $id ) = @_;
	
	$id		= sessionCleanID( $id );
	
	my $sfile	= storage( catfile( SESSION_DIR, $id ) );
	my $data	= -f $sfile ? fileRead( $sfile ) : '';
	
	return $data;
}

# Start session with ID, if given, or a fresh session
sub sessionStart {
	my ( $id ) = @_;
	
	state $start = 0;
	if ( $start ) {
		return;
	}
	
	# Get raw ID from cookie
	$id	//= getCookieData( 'session' );
	
	# Clean ID
	$id	= sessionCleanID( $id );
	
	# Mark started
	$start	= 1;
	
	if ( $id eq '' ) {
		# New session data
		sessionNew();
		return;
	}
	
	my $data = sessionRead( $id );
	
	# Invalid existing cookie? Reset
	if ( $data eq '' ) {
		sessionNew();
		return;
	}
	
	# Restore session from cookie
	sessionID( $id );
	
	my $values = jsonDecode( "$data" );
	foreach my $key ( keys %{$values} ) {
		sessionWrite( $key, $values->{$key} );
	}
}

# Get data by session key value
sub sessionGet {
	my ( $key ) = @_;
	
	sessionStart();
	my %data = sessionWrite();
	return $data{$key} //= '';
}

# Delete seession
sub sessionDestroy {
	my ( $id ) = @_;
	$id		= sessionCleanID( $id );
	
	my $sfile	= storage( catfile( SESSION_DIR, $id ) );
	if ( -f $sfile ) {
		unlink ( $sfile );
	}
}

# Garbage collection
sub sessionGC {
	my $sdir	= storage( SESSION_DIR );
	my $ntime	= time();
	
	# Time between cleaning up old cookies
	my $gc		= setting( 'session_gc', 'int', 3600 );
	
	opendir( my $dh, $sdir ) or exit 1;
	while ( readdir( $dh ) ) {
		my $file	= catfile( $sdir, $_ );
		if ( $file eq '.' or $file eq '..' ) {
			next;
		}
		
		if ( ! -f $file ) {
			next;
		}
		
		my @fstat	= stat( $file );
		if ( @fstat ) {
			if ( ( $ntime - $fstat[9] ) > $gc ) {
				unlink ( $file );
			}
		}
	}
	
	closedir( $dh );
}

# Finish and save session data, if it exists
sub sessionWriteClose {
	state $written	= 0;
	
	# Avoid double write and close
	if ( $written ) {
		return;
	}
	
	my %data	= sessionWrite();
	
	# Skip writing if there is no data
	if ( ! keys %data ) {
		return;
	}
	
	my $sdir	= storage( SESSION_DIR );
	unless ( -d $sdir ) {
		mkdir( $sdir, 0644 );
	}
	
	my $sfile	= storage( catfile( SESSION_DIR, sessionID() ) );
	fileWrite( $sfile, encode_json( \%data ) );
	
	$written = 1;
}

# Cleanup
END {
	sessionWriteClose();
}




# Response




# Template placeholder replacements
sub replace {
	my ( $tpl, $data, $clean ) = @_;
	
	while ( my ( $term, $html ) = each %$data ) {
		$tpl =~ s/\{$term\}/$html/ge;
	}
	
	$clean = $clean // 1;
	
	# Remove any unset placeholders
	if ( $clean == 1 ) {
		$tpl =~ s/\{.*\}//g;
	}
	
	return $tpl;
}

# Load and find rendering templates by label
sub template {
	my ( $label ) = @_;
	
	state %tpl_list = ();
	$label	= lc( $label );
	
	if ( keys %tpl_list ) {
		return $tpl_list{$label} //= '';
	}
	
	my $data	= getRawData();
	my $pattern	= qr/
	\s*(?<tpl>tpl_[\w_]+):\s*	# Template name E.G. tpl_page
		(?<html>.*?)		# HTML Content
	\s*end_tpl			# Template delimeter suffix
	/ixs;
	
	# Load templates list
	while ( $data =~ /$pattern/g ) {
		$tpl_list{$+{tpl}} = $+{html};
	}
	return $tpl_list{$label} //= '';
}

# Template rendering
sub render {
	my ( $tpl, $label, $params ) = @_;
	
	# Load from local templates if file template doesn't exist
	my $html = -f $tpl ? fileRead( $tpl ) : template( $label );
	
	return keys( %$params ) ? replace( $html, $params ) : $html;
}

# Set expires header
sub setCacheExp {
	my ( $ttl ) = @_;
	
	my $exp = dateRfc( time() + $ttl );
	print "Cache-Control: max-age=$ttl\n";
	print "Expires: $exp\n";
}

# Generate HTTP entity tag and related headers
sub genFileHeaders {
	my ( $rs ) = @_;
	if ( ! -f $rs ) {
		return;
	}
	
	my $fsize	= -s $rs;
	my $mtime	= ( stat( $rs ) )[9];
	my $lmod	= dateRfc( $mtime );
	
	# Similar to Nginx ETag algo
	my $etag		= 
	sprintf( "%x-%x", 
		$mtime		//= 0, 
		$fsize		//= 0
	);
	print "Content-Length: $fsize\n";
	print "Last-Modified: $lmod\n";
	print "ETag: $etag\n";
}

# Send HTTP status code
sub httpCode {
	my ( $code, $all ) = @_;
	state %http_codes	= ();
	
	$code			//= '501';
	$code			= "$code";
	
	# Preload HTTP status codes
	if ( !keys %http_codes ) {
		my $data = getRawData();
		my $pattern = qr/
		^(?<codes>--\s*HTTP\s*response\s*codes:\s*\n	# HTTP codes start
		.*?						# Code list
		\n--\s*End\s*response\s*codes\s*)		# End codes
		/ixsm;
	
		while ( $data =~ /$pattern/g ) {
			my $find = $+{codes};
			trim( \$find );
			
			while ( $find =~ /^(?<code>\S+)\s+(?<message>.*?)\s*$/mg ) {
				$http_codes{$+{code}}	= $+{message};
			}
		}
	}
	
	# If this is a list request only
	if ( defined( $all ) ) {
		return %http_codes;
	}
	
	# Check if status is currently present
	if ( !exists( $http_codes{$code} ) || $code eq '501' ) {
		print "Status: 501 Not Implemented\n";
		exit;
	}
	
	print "Status: $code $http_codes{$code}\n";
}

# Safety headers
sub preamble {
	my ( $skip_type, $min_csp ) = @_;
	
	# Base content security headers
	state %default_headers = (			
		'Content-Security-Policy'
					=>
			"default-src 'none'; base-uri 'self'; img-src *; font-src 'self'; " . 
			"style-src 'self' 'unsafe-inline'; script-src 'self'; " . 
			"form-action 'self'; media-src 'self'; connect-src 'self'; " . 
			"worker-src 'self'; child-src 'self'; object-src 'none'; " . 
			"frame-src 'self'; frame-ancestors 'self'",
		
		# These aren't usually necessary unless for a special web app
		'Permissions-Policy'	=> 
			"accelerometer=(none), camera=(none), geolocation=(none), "  . 
			"fullscreen=(self), gyroscope=(none), magnetometer=(none), " . 
			"microphone=(none), interest-cohort=(), payment=(none), usb=(none)",
		
		'Referrer-Policy'	=> "no-referrer strict-origin-when-cross-origin",
		
		'Strict-Transport-Security'
					=> "max-age=31536000; includeSubDomains",
		
		'X-Content-Type-Options'=> "nosniff",
		'X-Frame-Options'	=> "SAMEORIGIN",
		'X-XSS-Protection'	=> "1; mode=block"
	);
	
	my %sec_headers	= setting( 'sec_headers', 'hash', \%default_headers );
	
	# Default to not skipping content type
	$skip_type	//= 0;
	
	# Minimal Content-Security-Policy ( E.G. for error pages or images )
	$min_csp	//= 0;
	
	# Print security headers
	foreach my $header ( keys %sec_headers ) {
		
		# Minimal CSP
		if ( $header eq 'Content-Security-Policy' && $min_csp ) {
			print 
			"Content-Security-Policy: default-src 'none'; " . 
				"script-src 'self'; style-src 'self' 'unsafe-inline'; " . 
				"img-src 'self'\n";
		
		# Full CSP
		} else {
			print "$header: $sec_headers{$header}\n";
		}
	}
	
	if ( !$skip_type ) {
		# Default content type html, charset UTF-8
		print "Content-type: text/html; charset=UTF-8\n\n";
	}
}

# Redirect to another path
sub redirect {
	my ( $path ) = @_;
	httpCode( 303 );
	print "Location: $path\n\n";
	
	exit;
}

# Set the CORS origin to current URL
sub sendOrigin {
	my ( $realm, $root ) = @_;
	my %request	= getRequest();
	
	$realm		//= $request{'realm'};
	$root		//= '/';
	
	my $http = ( $request{'secure'} ) ? 'http://' : 'https://';
	my $path = $http . $realm . $root;
	print "Access-Control-Allow-Origin: $path\n";
}

# Send allowed options header in request mode and invalid method mode
sub sendOptions {
	my ( $fail, $allow ) = @_;
	
	# Set fail to off by default
	$fail	//= 0;
	$allow	//= 'GET, POST, HEAD, OPTIONS';
 
	# Fail mode?, send 405 HTTP status code, default 200 OK
	httpCode( $fail ? 405 : 200 );
	print $fail ? 
		"Allow: $allow\n" : 
		"Access-Control-Allow-Methods: $allow\n" . 
		"Access-Control-Allow-Headers: Accept, Accept-Language, Content-Type\n" . 
			"Access-Control-Expose-Headers: Content-Type, Cache-Control, Expires\n";
	exit;
}

# Response to invalid realm or other shenanigans
sub sendBadRequest {
	httpCode( 400 );
	preamble( 1 );
	
	# Don't need HTML for this
	print "Content-type: text/plain; charset=UTF-8\n\n";
	print "Bad Request";
	exit;
}

# Invalid file range request
sub sendRangeError {
	httpCode( 416 );
	preamble( 1 );
	print "Content-type: text/plain; charset=UTF-8\n\n";
	print "Invalid file range requested";
	exit;
}

# Test page response
sub sendTestResponse {
	httpCode( 200 );
	preamble( 1 );
	
	my $t = dateRfc();
	print "Content-type: text/plain; charset=UTF-8\n\n";
	print "Request complete: $t";
	exit;
}

# Send an HTTP code matching response file or text status
sub sendErrorResponse {
	my ( $realm, $verb, $code, $content ) = @_;
	
	httpCode( $code );
	
	if ( $verb eq 'head' ) {
		# No content in response to HEAD request
		exit;
	}
	
	# Try to send the realm-specific response file, if it exists
	my $tpl		= storage( catfile( 'sites', $realm, 'errors', "$code.html" ) );
	my $ctpl	= storage( catfile( 'errors', "$code.html" ) );
	if ( -f $tpl ) {
		preamble( 0, 1 );
		render( $tpl );
	
	# Or common error
	} elsif ( -f $ctpl ) {
		preamble( 0, 1 );
		render( $ctpl );
		
	# Default to plaintext
	} else {
		preamble( 1, 1 );
		print "Content-type: text/html; charset=UTF-8\n\n";
		print $content // '';
	}
	
	exit;
}

# File/directory not found page
sub sendNotFound {
	my ( $realm, $verb ) = @_;
	
	my %data	= (
		code	=> 404,
		message	=> 'Not Found',
		body	=> 'The page or folder you are trying to access could not be found.'
	);
	
	sendErrorResponse( 
		$realm, $verb, 404, 
		replace( template( 'tpl_error_page' ), \%data )
	);
}

# Access forbidden
sub sendForbidden {
	my ( $realm, $verb ) = @_;
	
	my %data	= (
		code	=> 403,
		message	=> 'Forbidden',
		body	=> 'Access to this resource is restricted.'
	);
	
	sendErrorResponse( 
		$realm, $verb, 403, 
		replace( template( 'tpl_error_page' ), \%data )
	);
}

# Authentication required
sub sendDenied {
	my ( $realm, $verb ) = @_;
	
	my %data	= (
		code	=> 401,
		message	=> 'Unauthorized',
		body	=> 'Access to this resource requires elevated privileges.'
	);
	
	sendErrorResponse( 
		$realm, $verb, 401, 
		replace( template( 'tpl_error_page' ), \%data )
	);
}

# Content page
sub sendPage {
	my ( $code, $out ) = @_;
	
	$code	//= 200;
	
	httpCode( $code );
	preamble();
	
	print $out;
}

# Simple send or buffered stream file
sub sendFile {
	my ( $rs, $stream ) = @_;
	
	# File stream buffer size
	my $bsize	= setting( 'buffer_size', 'int', 10240 );
	
	# Binary output and file opened in raw mode
	binmode( STDOUT );
	open( my $fh, '<:raw', $rs ) or exit 1;
	
	if ( $stream ) {
		my $buf;
		while ( read( $fh, $buf, $bsize ) ) {
			print $buf;
		}
	} else {
		while ( my $r = <$fh> ) {
			print $r;
		}
	}
	
	close( $fh );
	exit;
}

# Send ranged content
sub streamRanged {
	my ( $rs, $verb, $type, $ranges ) = @_;
	
	my $fsize	= -s $rs;
	my $fend	= $fsize - 1;
	
	# Total byte size
	my $totals	= 0;
	
	foreach my $r ( @{$ranges} ) {
		my ( $start, $end ) = @{$r};
		if ( 
			$start >= $fend ||
			( defined $end && $end >= $fend ) 
		) {
			sendRangeError();
		}
		
		$totals += ( defined $end ) ? 
			( $start - $end ) + 1 :
			( $fend - $start ) + 1;
	}
	
	if ( $totals > $fend ) {
		sendRangeError();
	}
	
	httpCode( 206 );
	
	# End here if this is a file range check only
	if ( $verb eq 'head' ) {
		exit;
	}
	
	preamble( 1, 1 );
	
	# Generate content boundary
	my $bound	= sha1_hex( $rs . $type );
	
	print "Accept-Ranges: bytes\n";
	print "Content-Type: multipart/byteranges; boundary=$bound\n";
	print "Content-Length: $totals\n";
	
	# Binary output and file opened in raw mode
	binmode( STDOUT );
	open( my $fh, '<:raw', $rs ) or exit 1;
	
	my $bsize	= setting( 'buffer_size', 'int', 10240 );
	my $limit	= 0;
	my $buf;
	my $chunk;
	local $|	= 1;	# Temporarily disable output buffering
	
	foreach my $range ( @{$ranges} ) {
		my ( $start, $end ) = @{$range};
		
		print "\n--$bound\n";
		print "Content-type: $type\n\n";
		
		if ( defined $end ) {
			$limit = $end - $start + 1;
			print "Content-Range: bytes $start-$end/$fsize\n";
		} else {
			$limit = $fend - $start + 1;
			print "Content-Range: bytes $start-$fend/$fsize\n";
		}
		
		# Move to start position
		my $cursor = seek( $fh, $start, SEEK_SET );
		if ( ! $cursor ) {
			close( $fh );
			exit 1;
		}
		
		# Send chunks until end of range
		while ( $limit > 0 ) {
			# Reset chunk size until below max buffer size
			$chunk	= $limit > $bsize ? $bsize : $limit;
			
			my $ld	= read( $fh, $buf, $chunk );
			if ( !defined( $ld ) || $ld == 0 ) {
				# Something went wrong while reading 
				# TODO : Log the error
				close( $fh );
				exit 1;
			}
			
			print $buf;
			$limit -= $ld;
		}
	}
	
	close( $fh );
	exit;
}

# Send static file
sub sendResource {
	my ( $rs, $realm, $verb ) = @_;
	
	# Try to get the file extension
	my ( $name, $dir, $ext ) = fileparse( $rs, qr/\.[^.]*/ );
	$ext =~ s/\.//g;
	
	# Empty extension?
	if ( $ext eq '' ) {
		sendNotFound( $realm, $verb );
	}
	
	# Mime type
	my %mime_list	= mimeList();
	my $type	= $mime_list{$ext}{type} //= '';
	
	# Not in whitelist?
	if ( $type eq '' ) {
		sendNotFound( $realm, $verb );
	}
	
	# Scan for file request ranges
	my @ranges = requestRanges();
	if ( @ranges ) {
		streamRanged( $rs, $verb, $type, \@ranges );
	}
	
	# Test for type (has file signatures or "magic numbers")
	# Types without signatures are treated as text
	my $text = exists( $mime_list{$ext}{sig} ) ? 0 : 1;
	
	httpCode( 200 );
	if ( !$text ) {
		# Allow ranges for non-text types
		print "Accept-Ranges: bytes\n";
	}
	
	# End here if sending is not necessary
	if ( $verb eq 'head' ) {
		exit;
	}
	
	genFileHeaders( $rs );
	preamble( 1, 1 );
	
	# Send the file content type header
	print "Content-type: $type\n\n";
	
	# Send text as-is
	if ( $text ) {
		sendFile( $rs, 0 );
	}
	
	# Buffered stream
	sendFile( $rs, 1 );
}




# Formatting




# Get allowed HTML tags
sub allowedTags {
	state %whitelist;
	
	if ( keys %whitelist ) {
		return %whitelist;
	}
	
	state %default_whitelist = (
		"p"		=> [ "style", "class", "align", 
				"data-pullquote", "data-video", 
				"data-media" ],
		
		"div"		=> [ "style", "class", "align" ],
		"span"		=> [ "style", "class" ],
		"br"		=> [ "style", "class" ],
		"hr"		=> [ "style", "class" ],
		
		"h1"		=> [ "style", "class" ],
		"h2"		=> [ "style", "class" ],
		"h3"		=> [ "style", "class" ],
		"h4"		=> [ "style", "class" ],
		"h5"		=> [ "style", "class" ],
		"h6"		=> [ "style", "class" ],
		
		"strong"	=> [ "style", "class" ],
		"em"		=> [ "style", "class" ],
		"u"		=> [ "style", "class" ],
		"strike"	=> [ "style", "class" ],
		"del"		=> [ "style", "class", "cite" ],
		
		"ol"		=> [ "style", "class" ],
		"ul"		=> [ "style", "class" ],
		"li"		=> [ "style", "class" ],
		
		"code"		=> [ "style", "class" ],
		"pre"		=> [ "style", "class" ],
		
		"sup"		=> [ "style", "class" ],
		"sub"		=> [ "style", "class" ],
		
		"a"		=> [ "style", "class", "rel", 
				"title", "href" ],
		
		"img"		=> [ "style", "class", "src", "height", "width", 
				"alt", "longdesc", "title", "hspace", 
				"vspace", "srcset", "sizes",
				"data-srcset", "data-src", 
				"data-sizes" ],
		"figure"	=> [ "style", "class" ],
		"figcaption"	=> [ "style", "class" ],
		"picture"	=> [ "style", "class" ],
		
		"table"		=> [ "style", "class", "cellspacing", 
					"border-collapse", 
					"cellpadding" ],
		"thead"		=> [ "style", "class" ],
		"tbody"		=> [ "style", "class" ],
		"tfoot"		=> [ "style", "class" ],
		"tr"		=> [ "style", "class" ],
		"td"		=> [ "style", "class", "colspan", 
				"rowspan" ],
		"th"		=> [ "style", "class", "scope", 
				"colspan", "rowspan" ],
		
		"caption"	=> [ "style", "class" ],
		"col"		=> [ "style", "class" ],
		"colgroup"	=> [ "style", "class" ],
		
		"summary"	=> [ "style", "class" ],
		"details"	=> [ "style", "class" ],
		
		"q"		=> [ "style", "class", "cite" ],
		"cite"		=> [ "style", "class" ],
		"abbr"		=> [ "style", "class" ],
		"blockquote"	=> [ "style", "class", "cite" ]
	);
	
	%whitelist	= setting( 'tag_whitelist', 'hash', \%default_whitelist );
	return %whitelist;
}

# Wrap sent HTML with protected placeholders, optionally adding new tags
sub startProtectedTags {
	my ( $html, $ns )	= @_;
	
	# Base level protected tags
	state @protected	= 
	( 'p', 'ul', 'ol', 'pre', 'code', 'table', 'figure', 'figcaption', 
		'address', 'details', 'span', 'embed', 'video', 'audio', 
		'texteara', 'input' );
	
	if ( $ns ) {
		@protected = @{ mergeArrayUnique( \@protected, $ns ) };
	}
	
	my $tags	= join( '|', @protected );
	
	# Wrap protected tags in placeholders
	$$html		=~ 
	s|(<($tags)[^>]*>.*?</\2>)|__PROTECT__$1__ENDPROTECT__|gs;
}

# Restore protected tags
sub endProtectedTags {
	my ( $html )		= @_;
	
	$$html		=~ s/__PROTECT__(.*?)__ENDPROTECT__/$1/g;
}

# Format code to HTML
sub escapeCode {
	my ( $code ) = @_;
	
	return '' if !defined( $code ) || $code eq ''; 
	
	if ( !Encode::is_utf8( $code ) ) {
		$code = Encode::decode( 'UTF-8', $code );
	}
	
	# Double esacped ampersand workaround
	$code =~ s/&(?!(amp|lt|gt|quot|apos);)/&amp;/g; 
	
	$code =~ s/</&lt;/g;
	$code =~ s/>/&gt;/g;
	$code =~ s/"/&quot;/g;
	$code =~ s/'/&apos;/g;
	$code =~ s/\\/&#92;/g;
	
	$code =~ s/([^\x00-\x7F])/sprintf("&#x%X;", ord($1))/ge;
	trim( \$code );
	
	return $code;
}

# TODO: Process footnotes
sub footnote {
	my ( $ref, $note ) = @_;
	
	return '';
}

# Extract subtitles or captions
sub extractCC {
	my ( $urls )	= @_;
	my @subs	= map { [split(/:/, $_)] } split(/,\s*/, $urls );
	my $out		= '';
	
	foreach my $track ( @$subs ) {
		my %data	= {};
		my $len		= scalar( $track );
		
		# Only a track
		if ( $len == 1 ) {
			%data	= (
				src		= @$track[0],
				isdefault	= ''
			);
			
			$out	.= 
			replace( template( 'tpl_cc_nl_embed' ), %data );
			next;
		}
		
		# Not a language, but is default
		if ( $len == 2 && lc( @$track[1] ) eq 'default' ) {
			%data	= (
				src		= @$track[0],
				isdefault	= 'default'
			);
			
			$out	.= 
			replace( template( 'tpl_cc_nl_embed' ), %data );
			next;
		
		# Language, but not default
		} elsif ( $len == 2 ) {
			%data	= (
				src		= @$track[0],
				lang		= @$track[1],
				isdefault	= ''
			);
			
			$out	.= 
			replace( template( 'tpl_cc_embed' ), %data );
			next;
		}
		
		# Language and is default
		%data	= (
			src		= @$track[0],
			lang		= @$track[1],
			isdefault	= 'default'
		);
		$out	.= replace( template( 'tpl_cc_embed' ), %data );
	}
	
	return $out;
}

# Process uploaded media embeds
sub embeds {
	my ( $ref, $source, $title, $captions, $preview ) = @_;
	my %data	= (
		src	=> $source,
		title	=> $title,
		preview	=> $preview,
		detail	=> extractCC( $captions )
	);
	
	for ( $ref ) {
		/audio/ and do {
			return replace( template( 'tpl_audio_embed' ), %data );
		};
		
		/video/ and do {
			return ( $preview eq '' ) ?
			replace( template( 'tpl_video_np_embed' ), %data ) : 
			replace( template( 'tpl_video_embed' ), %data );
		};
	}
	
	# Some matching went wrong
	return '';
}

# Third-party hosted media embedding
sub hostedEmbeds {
	my ( $host, $url ) = @_;
	my @pats;
	
	for ( $host ) {
		/youtube/ and do {
			@pats = (
				qr/(?:https?\:\/\/(www\.)?)?
					youtube\.com\/watch\?v=
					(?<src>[0-9a-z_\-]*)
					(?:\&t\=(?<time>[\d]*)s)?/is,
				qr/(?:https?\:\/\/(www\.)?)?
					youtu\.be\/
					(?<src>[0-9a-z_\-]*)
					(?:\?t\=(?<time>[\d]*))?/is,
				qr/(?<src>[0-9a-z_\-]*)/is
			);
			
			# Try to find a matching YouTube URL
			foreach my $rx ( @pats ) {
				if ( $url =~ $rx ) {
					return 
					replace( template( 'tpl_youtube' ), %+ );
				}
			}
			
			# Or just return the URL as-is
			return '[youtube ' . $url . ']';
		};
		
		/vimeo/ and do {
			@pats = (
				qr/(?:https?\:\/\/(www\.)?)?
				vimeo\.com\/(?<src>[0-9]*)/is,
				qr/(?<src>[0-9]*)/is
			);
			
			foreach my $rx ( @pats ) {
				if ( $url =~ $rx ) {
					return 
					replace( template( 'tpl_vimeo' ), %+ );
				}
			}
			
			return '[vimeo ' . $url . ']';
		};
		
		/peertube/ and do {
			if ( $url =~ qr/(?:https?\:\/\/(www\.)?)?
					(?<src_host>.*?)\/videos\/watch\/
					(?<src>[0-9\-a-z_]*)\]/is ) {
				return 
				replace( template( 'tpl_peertube' ), %+ );
			}
			
			return '[peertube ' . $url . ']';
		};
		
		/archive/ and do {
			@pats = (
				qr/(?:https?\:\/\/(www\.)?)?
					archive\.org\/details\/
					(?<src>[0-9\-a-z_\/\.]*)\]/is,
				qr/(?<src>[0-9a-z_\/\.]*)\]/is
			);
			
			foreach my $rx ( @pats ) {
				if ( $url =~ $rx ) {
					return 
					replace( template( 'tpl_archiveorg' ), %+ );
				}
			}
			
			return '[archive ' . $url . ']';
		};
		
		/lbry|odysee/ and do {
			@pats = (
				qr/(?:https?\:\/\/(www\.)?)?
					(?<src_host>.*?)\/\$\/download\/
					(?<slug>[\pL\pN\-_]*)\/\-?
					(?<src>[0-9a-z_]*)\]/is,
				qr/lbry\:\/\/\@(?<src_host>.*?)\/([\pL\pN\-_]*)
					(?<slug>\#[\pL\pN\-_]*)?(\s|\/)
					(?<src>[\pL\pN\-_]*)\]/is
			);
			
			foreach my $rx ( @pats ) {
				return replace( template( 'tpl_lbry' ), %+ );
			}
			
			return '[lbry ' . $url . ']';
		};
		
		/utreon|playeur/ and do {
			if ( $url =~ qr/(?:https?\:\/\/(www\.)?)?
					(?:utreon|playeur)\.com\/v\/
					(?<src>[0-9a-z_\-]*)
					(?:\?t\=(?<time>[\d]{1,}))?\]/is 
			) {
				return replace( template( 'tpl_playeur' ), %+ );
			}
			
			return '[playeur ' . $url . ']';
		};
	}
	
	# Nothing else found
	return '';
}

# Table data row
sub formatRow {
	my ( $row, $header )	= @_;
	$header		//= 0;
	
	my $tag		= $header ? 'th' : 'td';
	
	# Split on pipe symbol, skipping escaped pipes '\|'
	my @data	= split( /(?<!\\)\|/, $row );
	my $html	= join( '', map { "<$tag>$_</$tag>" } @data );
	
	return "<tr>$html</tr>\n";
}

# Convert ASCII table to HTML
sub formatTable {
	my ( $table ) = @_;
	my $html	= '';
	
	# Lines = Rows
	my @rows	= split( /\n/, $table );
	
	# In header row, if true
	my $first	= 1;
	
	foreach my $row ( @rows ) {
		# Trim
		trim( \$row );
		
		# Skip empty rows or lines with just separator
		next if $row eq '' || $row =~ /^(\+|-)+$/;
		
		# First round is the header
		$html	.= formatRow( $row, $first );
		next unless $first;
		
		$first	= 0;
	}
	
	return "<table>$html</table>\n";
}

# Close open list types
sub formatCloseList {
	my ( $lstack, $indent, $html, $ltype ) = @_;
	while (
		@$lstack				&&
		$lstack->[-1]{indent} > $indent		&&
		$lstack->[-1]{type} eq $ltype
	) {
		$$html .= "</$ltype>\n";
		pop @$lstack;
	}
}

# Create new list type
sub formatNewList {
	my ( $lstack, $html, $indent, $ltype ) = @_;
	if (
		!@$lstack				||
		$lstack->[-1]{type} ne $ltype		||
		$lstack->[-1]{indent} != $indent
	) {
		# Close the current list if needed
		if ( @$lstack && $lstack->[-1]{type} eq $ltype ) {
			$$html .= "</$ltype>\n"
		}
		
		# Start a new list
		$$html .= "<$ltype>\n";
		push( @$lstack, { type => $ltype, indent => $indent } ) ;
	}
}

# Finish closing any remaining open list types based on stack
sub formatEndLists {
	my ( $lstack, $html ) = @_;
	while ( @$lstack ) {
		$$html .= 
		( $lstack->[-1]{type} eq 'ul' ) ? '</ul>' : (
			( $lstack->[-1]{type} eq 'ol' ) ? '</ol>' : '</dl>'
		);
		pop @$lstack;
	}
}

# Convert indented lists into HTML lists
sub formatListBlock {
	my ( $text ) = @_;

	my @lines = split /\n/, $text;
	my $html = '';
	my @lstack;  # Stack to manage nested lists
	
	foreach my $line ( @lines ) {
		# Match ordered list items
		if ( $line =~ /^(\s*)([\*\+\d\.]+)\s+(.*)$/ ) {
			my $indent	= length( $1 );
			my $marker	= $2;
			my $content	= $3;
			
			# Unordered type
			if ( $marker =~ /^[\*\+]/ ) {
				# Close ordered list if needed
				formatCloseList( \@lstack, \$html, $indent, 'ol');
				
				# Start a new unordered list if needed
				formatNewList( \@lstack, \$html, $indent, 'ul');
			
			# Ordered type
			} else {
				# Close unordered list if needed
				formatCloseList( \@lstack, \$html, $indent, 'ul');
				
				# Start a new ordered list if needed
				formatNewList( \@lstack, \$html, $indent, 'ol');
			}
			$html .= "<li>$content</li>\n";
			next;
		}
		
		# Close any remaining open lists before adding non-list content
		formatEndLists( \@lstack, $html );
		$html .= "$line\n";
	}

	# Close any remaining open lists at the end
	formatEndLists( \@lstack, \$html );
	return $html;
}

# Convert plain text lists to HTML list blocks
sub formatLists {
	my ( $text )	= @_;
	my @lists;
	
	# Prevent formatting inside existing block level tags
	startProtectedTags( \$text );
	
	# Save a placeholder after finding each list block
	while ( $text =~ /(__PROTECT__(.*?)__ENDPROTECT__)|([^\r\n]+)/g ) {
		if ( !defined( $3 ) ) {
			next;
		}
		
		my $idx	= scalar( @lists );
		push( @lists, { index => $idx, html => $3 } );
		$text =~ s/$&/__STARTLIST__${idx}__ENDLIST__/;
	}
	
	for my $block ( @lists ) {
		# Format the non-protected text block
		$block->{html} = formatListBlock( $block->{html} );
		
		# Restore from placeholder
		$text =~ 
		s/__STARTLIST__$block->{index}__ENDLIST__/$block->{html}/g;
	}
	
	# Restore other block level tags
	endProtectedTags( \$text );
	return $text;
}

# Wrap body text and line breaks in paragraphs
sub makeParagraphs {
	my ( $html, $ns )	= @_;
	
	startProtectedTags( \$html, $ns );
	
	# Wrap paragraphs
	$html		=~ 
	s/(?<!__PROTECT__)\r?\n\s*\r?\n(?!__ENDPROTECT__)/<\/p><p>/g;
	
	$html		= 
	"<p>$html</p>" unless $html =~ /^<p>/ || $html =~ /__PROTECT__/;
	
	endProtectedTags( \$html );
	return $html;
}

# Simple subset of Markdown formatting with embedded media extraction
sub markdown {
	my ( $data ) = @_;
	
	return '' if !defined( $data ) || $data eq ''; 
	
	trim( \$data );
	return '' if $data eq '';
	
	state %patterns = (
		# Links, Images
		qr/(?<img>\!)?						# Image if present
			\[(?<text>[^\]]+)\]				# Main text
			(?:\(
				(?:\"(?<title>([^\"]|\\\")+)\")?	# Alt or title
				(?<dest>.*?)\)				# Destination URL
			)
		/ixs
		=> sub {
			my $text	= $+{text};
			my $dest	= $+{dest};
			my $img		= $+{img}	// '';
			my $title	= $+{title}	// '';
			
			# Image?
			if ( $img ne '' ) {
				if ( $title ne '' ) {
					return '<img src="' . $dest . 
						' title="' . $title . '">';
				}
				return '<img src="' . $dest . '">';
			}
			
			# Link with title?
			if ( $title ne '' ) {
				return 
				'<a href="'. $dest . '" title="' . 
					$title . '">' . $text . '</a>';
			}
			
			# Plain link
			return '<a href="'. $dest . '">' . $text . '</a>';
		},
		
		# Bold, Italic, Delete, Quote
		'(\*(\*+)?|\~\~|\:\")(.*?)\1'
		=> sub {
			for ( $1 ) {
				/\~/ and do { return '<del>' . $1 . '</del>'; };
				/\:/ and do { return '<q>' . $1 . '</q>'; };
			}
			
			my $i = strsize( $1 );
			for ( $i ) {
				( $i == 2 ) and do { return '<strong>' . $3 . '</strong>'; };
				( $i == 3 ) and do { return '<strong><em>' . $3 . '</em></strong>'; };
			}
			return '<em>' . $3 . '</em>';
		},
		
		# Headings
		'(^|\n)(?<delim>[#=]{1,6})\s?(?<text>.*?)\s?\2?\n' 
		=> sub {
			my $level	= length( $+{delim} );	# Indent depth
			my $text	= $+{text};		# Heading
			
			trim( \$text );
			
			return "<h$level>$text</h$level>";
		},
		
		# Inline code
		'`(?<code>[^`]*)`' 
		=> sub {
			my $code = escapeCode( $+{code} );
			return "<code>$code</code>";
		},
		
		# Multi-line code
		'^|\n```(?<code>.*?)```'
		=> sub {
			my $code = escapeCode( $+{code} );
			return "<pre><code>$code</code></pre>";
		}, 
		
		# Templates
		'(?<!\\\\)\{\{(.*?)\}\}(?<!\\\\)'
		=> sub {
			my ( $tpl, $opts ) = @_;
			if ( $opts ) {
				# TODO: Parse options
				return "<span class=\"template\" $opts>$tpl</span>";
			} else {
				return "<span class=\"template\">$tpl</span>";
			}
		}, 
		
		# Tables
		'(\+[-\+]+[\+\-]+\s*\|\s*.+?\n(?:\+[-\+]+[\+\-]+\s*\|\s*.+?\n)*)'
		=> sub {
			return formatTable( $_[0] );
		},
		
		# Horizontal rule
		'(?<!\\\\)([\-_]{4,})(?=\r?\n)'
		=> sub {
			return '<hr />';
		},
		
		# Uploaded media embedding
		# Matches in order:
		# Embed type, alt or title, source URL, preview image, subtitles or captions
		qr/\[
			(?<ref>audio|video)(\s*)?:(\s*)?(?<title>[^\]]*)\]	# Embed type and title
			\((?<source>[^"]+)					# Source URL
			(?:\s+"(?<preview>.*?)")?				# Preview image, if present
			(?:\s+"(?<captions>(?:[^\"]+:?[^\"]*(?:,\s*[^\"]+:?[^\"]*)*))")?
		\)/ixs
		=> sub {
			
			# Reference type
			my $ref		= $+{ref};
			
			# Source URL
			my $source	= $+{source}	// '';
			
			# Detail
			my $title	= $+{title}	// '';
			my $preview	= $+{preview}	// '';
			my $captions	= $+{captions}	// '';
			
			trim( \$ref );
			
			return 
			embeds( $ref, $source, $title, $captions, $preview );
		},
		
		# References, figures, third party embeds etc...
		qr/
			\[
				(?<ref>[^\]\[\"\s]+)			# Reference or embed marker
				(?:\"(?<title>([^\"]|\\\")+)\")?	# Alt or title
				(?:\[(?<caption>.*?)\] )?		# Caption(s), if present
				(?<source>.*?)				# Source URL or note
			\]
		/ixs
		=> sub {
			my $ref		= $+{ref};
			my $source	= $+{source}	// '';
			my $title	= $+{title}	// '';
			my $caption	= $+{caption}	// '';
			
			trim( \$ref );
			
			for ( $ref ) {
				# TODO: Process footnotes
				/ref|footnote/ and do { 
					return 'footnote'; 
				};
				
				# Embedded figure with caption
				/figure/ and do { 
					my %data	= (
						src	=> $source,
						alt	=> $title,
						caption	=> $caption
					);
					
					return 
					replace( template( 'tpl_figure_embed' ), %data );
				};
				
				# Third-party hosted media embedding
				/youtube|vimeo|archive|peertube|lbry|odysee|utreon|playeur/ and do {
					return hostedEmbeds( $ref, $source );
				};
			}
			
			return '';
		},
		
		# Wiki-style link
		'(?<!\\\\)\[\s*([^\]\|]+?)\s*(?:\|\s*([^\]]+?))?\s*\](?<!\\\\)' 
		=> sub {
			my ( $url, $text )  = ( $1, $2 );
			$text ||= $url;
			
			return '<a href="'. $url . '">' . $text . '</a>';
		}
	);
	
	# Replace placeholders with formatted HTML
	foreach my $pat ( keys %patterns ) {
		my $subr	= $patterns{$pat};
		if ( $pat =~ /<\w+>/ ) {
			# Named captures
			$data =~ s/$pat/sub { $subr->(%+) }/ge;
		} else {
			# All else
			$data =~ s/$pat/sub { $subr->($&) }/ge;
		}
	}
	
	# Format lists
	$data = formatLists( $data );
	
	# Wrap paragraphs
	return makeParagraphs( $data );
}

# Generate pagination link data
sub paginate {
	my ( $total, $idx, $show )	= @_;
	
	# Total number of pages
	$total		||= 1;
	
	# Current page index
	$idx		||= 1;
	
	# Maximum number of page links to show
	$show		||= 5;
	
	# Range of pages to show
	my $half	= int( $show / 2 );
	my $start_page	= $idx - $half;
	my $end_page	= $idx + $half;
	
	# List of page items
	my @links;
	
	# Limit display ranges
	if ( $start_page < 1 ) {
		$start_page	= 1;
		$end_page	= $show < $total ? $show : $total;
	}
	
	if ( $end_page > $total ) {
		$end_page = $total;
		if ( $total - $show + 1 > 0 ) {
			$start_page = $total - $show + 1;
		}
	}
	
	if( $idx > 1 ) {
		push( @links, { 
			text		=> '{page_first}', 
			page		=> 1,
			is_current	=> 0
		} );
		
		if ( $idx > 2 ) {
			push( @links, { 
				text		=> '{page_previous}', 
				page		=> $idx - 1,
				is_current	=> 0
			} );
		}
	}
	
	for my $i ( $start_page .. $end_page ) {
		push( @links, { 
			text		=> $i, 
			page		=> $i,
			is_current	=> $i == $idx
		} );
	}
	
	if ( $idx < $total )
		if ( $idx + 1 < $total ) {
			push( @links, { 
				text		=> '{page_next}', 
				page		=> $idx + 1,
				is_current	=> 0
			} );
		}
		
		push( @links, { 
			text		=> '{page_last}', 
			page		=> $total,
			is_current	=> 0
		} );
	}
	
	return @links;
}




# User functionality




# Generate random salt up to given length
sub genSalt {
	my ( $len ) = @_;
	state @pool	= ( '.', '/', 0..9, 'a'..'z', 'A'..'Z' );
	
	return join( '', map( +@pool[rand( 64 )], 1..$len ) );
}

# Generate HMAC digest
sub hmacDigest {
	my ( $key, $data )	= @_;
	my $hmac		= hmac_sha384( $data, $key );
	
	return unpack( "H*", $hmac );
}

# Generate a hash from given password and optional salt
sub hashPassword {
	my ( $pass, $salt, $rounds ) = @_;
	
	# Generate new salt, if empty
	$salt		//= genSalt( 16 );
	$rounds		//= HASH_ROUNDS;
	
	# Crypt-friendly blocks
	my @chunks	= 
		split( /(?=(?:.{8})+\z)/s, sha512_hex( $salt . $pass ) );
	
	my $out		= '';	# Hash result
	my $key		= '';	# Digest key per block
	my $block	= '';	# Hash block
	
	for ( @chunks ) {
		# Generate digest with key from crypt
		$key	= crypt( $_, substr( sha256_hex( $_ ), 0, -2 ) );
		$block	= hmacDigest( $key, $_ );
		
		# Generate hashed block from digest
		for ( 1..$rounds ) {
			$block	= sha384_hex( $block );
		}
		
		# Add block to output
		$out		.= sha384_hex( $block );
	}
	
	return $salt . ':' . $rounds . ':' . $out;
}

# Match raw password against stored hash
sub verifyPassword {
	my ( $pass, $stored ) = @_;
	
	my ( $salt, $rounds, $spass ) = split( /:/, $stored );
	
	if ( $stored eq hashPassword( $pass, $salt, $rounds ) ) {
		return 1;
	}
	
	return 0;
}

# Find password for an existing user
sub getPassword {
	my ( $user, $realm ) = @_;
	
	my $pass = '';
	
	my $file = storage( catfile( $realm, USER_FILE ) );
	
	open( my $lines, '<:encoding(UTF-8)', $file ) or exit 1;
	while ( <$lines> ) {
		my ( $u, $p ) = $_ =~ /(.*)\t(.*)/;
		
		if ( $user eq $u ) {
			$pass = $p;
			last;
		}
	}
	
	close ( $lines );
	return $pass;
}


# Save new user with password or edit existing 
sub savePassword {
	my ( $user, $pass, $realm ) = @_;
	
	$pass		= hashPassword( $pass );
	
	# Username with matching password
	my $npass	= "$user	$pass\n";
	
	my $ifile	= storage( catfile( $realm, USER_FILE ) );
	
	# Try to get a lock for this user file
	fileLock( $ifile, 1 ) or exit 1;
	
	# No user file for this realm? Create it
	if ( ! -f $ifile ) {
		open( INF, '>:encoding(UTF-8)', $ifile ) or exit 1;
		close( INF );
	}
	
	open( INF, '<:encoding(UTF-8)', $ifile ) or exit 1;
	
	my $ofile	= storage( catfile( $realm, USER_FILE . '.new' ) );
	open( ONF, '>:encoding(UTF-8)', $ofile ) or exit 1;
	
	my $found	= 0;
	
	# Find if user exists
	while ( my $line = <INF> ) {
		# Append line as-is if password already changed
		if ( $found ) {
			print ONF $line;
			next;
		}
		
		# Check current user/pass combination
		my ( $u, $p ) = $line =~ /(.*)\t(.*)/;
		if ( $user eq $u ) {
			$found	= 1;
			
			# Swap existing line with new pair
			print ONF $npass;
			next;
		}
		
		# Continue copying
		print ONF $line;
	}
	
	close( INF );
	
	# New record? Add to the end
	if ( !$found ) {
		print ONF $npass;
	}
	
	close( ONF );
	
	# Change current user file to backup and make new file current
	copy( $ifile, $ifile . '.bak' ) or exit 1;
	move( $ofile, $ifile ) or exit 1;
	
	# Clear lock
	fileLock( $ifile, 0 );
}

# Create a new user login if username doesn't exist
sub newLogin {
	my ( $user, $pass, $realm ) = @_;
	$pass	= password( $pass );
	$realm	//= '';
	
	my $existing = getPassword( $user, $realm );
	
	if ( $existing ne '' ) {
		return 0;
	}
	
	savePassword( $user, $pass, $realm );
	return 1;
}

# Update existing user login
sub updateLogin {
	my ( $user, $newpass, $oldpass, $realm ) = @_;
	$realm	//= '';
	
	my $existing = getPassword( $user, $realm );
	
	if ( $existing eq '' ) {
		return 0;
	}
	
	if ( ! verifyPassword( $oldpass, $existing ) ) {
		return 0;
	}
	
	savePassword( $user, $newpass, $realm );
	return 1;
}



# Route handling



# URL Router
sub route {
	my %request	= getRequest();
	my $verb	= $request{'verb'};
	
	# Unkown request method? 
	sendOptions( 1 ) unless exists $path_map{$verb};
	
	my $realm	= $request{'realm'};
	my $url		= $request{'url'};
	
	$url		= unifySpaces( $url );
	
	# Trim leading backslashes and escape any in the middle
	$url		=~ s/\/$//;
	$url		=~ s/\\/\\\\/g;
	
	# Begin router
	foreach my $route ( @{$path_map{$verb}} ) {
		unless ( $route->{path} && $route->{handler} ) {
			next;
		}
		
		my $path	= $route->{path};
		my $handler	= $route->{handler};
		
		trim( \$path );
		trim( \$handler );
		
		# Replace URL routing placeholders
		$path =~ s/$_/\Q$markers{$_}\E/g for keys %markers;
		
		# Path matched?
		if ( $url =~ m/^$path$/ ) {
			my %params	= %+;
			if ( defined( &{$handler} ) ) {
				&{$handler}( $realm, $verb, %params );
				exit;
			}
			
			# Path matched, but no handler?
			sendNotFound( $realm, $verb );
		}
	}
	
	# Nothing matched
	sendNotFound( $realm, $verb );
}




# View routes





# Create a typical response for a limited access view, E.G. login page etc...
sub safeView {
	my ( $realm, $verb ) = @_;
	
	if ( $verb eq 'options' ) {
		httpCode( '204' );
		sendOptions();
		setCacheExp( 604800 );
		sendOrigin( $realm );
		exit;
	}
	
	httpCode( '200' );
	if ( $verb eq 'head' ) {
		# Nothing else to send
		exit;
	}
	
	sendOrigin( $realm );
	preamble();
}

# Static/Uploaded file routes
sub viewStatic {
	my ( $realm, $verb, $params ) = @_;
	
	if ( $verb eq 'options' ) {
		sendOptions( 0, 'GET, HEAD, OPTIONS' );
	}
	
	my $tree	= $params->{'tree'} //= '';
	my $file	= $params->{'file'} //= '';
	
	my $loc	= 
	storage( 
		catfile( 'sites', $realm, 'static', $tree, $file ) 
	);
	
	if ( ! -f $loc ) {
		# Fallback to uploads path
		$loc = 
		storage( 
			catfile( 'sites', $realm, UPLOADS, $tree, $file ) 
		);
	}
	
	# Fallback failed
	if ( ! -f $loc ) {
		sendNotFound( $realm, $verb );
	}
	
	sendResource( $loc, $realm, $verb );
	exit;
}

# TODO: Homepage
sub viewHome {
	my ( $realm, $verb, $params ) = @_;
	
	# Send options, if asked
	# TODO: Limit options based on realm
	if ( $verb eq 'options' ) {
		sendOptions( 0, 'GET, HEAD, OPTIONS' );
	}
	
	httpCode( 200 );
	
	sessionStart();
	
	my $stime = sessionGet( 'start' );
	if ( $stime eq '' ) {
		$stime = time();
		sessionWrite( 'start', $stime );
	}
	
	preamble();
	my $out	= '';
	foreach my $key ( keys %$params ) {
		$out .= "<p>$key: $params->{$key}</p>";
	}
	
	my %data = (
		realm	=> $realm,
		body	=> $out
	);
	
	
	my $tpl = storage( catfile( 'sites', $realm, 'pages', 'home.html' ) );
	
	print render( $tpl, 'tpl_page', \%data );
	exit;
}

# TODO: Login page
sub viewLogin {
	my ( $realm, $verb, $params ) = @_;
	safeView( $realm, $verb );
	
	print "Login page";
}

# TODO: Execute login
sub doLogin {
	my ( $realm, $verb, $params ) = @_;
	if ( $verb eq 'options' ) {
		sendOptions( 0, 'POST, OPTIONS' );
	}
	
	httpCode( 200 );
	preamble();
	foreach my $key ( keys %$params ) {
		print "<p>$key: $params->{$key}</p>";
	}
}

# TODO: Register page
sub viewRegister {
	my ( $realm, $verb, $params ) = @_;
	safeView( $realm, $verb );
	
	print "Register page";
}

# TODO: Execute registration
sub doRegister {
	my ( $realm, $verb, $params ) = @_;
	if ( $verb eq 'options' ) {
		sendOptions( 0, 'POST, OPTIONS' );
	}
	
	httpCode( 201 );
	preamble();
	foreach my $key ( keys %$params ) {
		print "<p>$key: $params->{$key}</p>";
	}
}

# TODO: New post page
sub viewNewPost {
	my ( $realm, $verb, $params ) = @_;
	safeView( $realm, $verb );
	
	print "New post page";
}

# TODO: Execute new post
sub doNewPost {
	my ( $realm, $verb, $params ) = @_;
	if ( $verb eq 'options' ) {
		sendOptions( 0, 'POST, OPTIONS' );
	}
	
	httpCode( 201 );
	preamble();
	foreach my $key ( keys %$params ) {
		print "<p>$key: $params->{$key}</p>";
	}
}

# TODO: Editing existing page
sub viewEditPost {
	my ( $realm, $verb, $params ) = @_;
	safeView( $realm, $verb );
	
	print "Editing post page";
}

# TODO: Execute editing post
sub doEditPost {
	my ( $realm, $verb, $params ) = @_;
	if ( $verb eq 'options' ) {
		sendOptions( 0, 'POST, OPTIONS' );
	}
	
	httpCode( 201 );
	preamble();
	foreach my $key ( keys %$params ) {
		print "<p>$key: $params->{$key}</p>";
	}
}


route();

# End of script
END {
	hook( { event => 'perlite_shutdown' } );
}




__DATA__


Configuration and lists:
The following is a set of settings used to serve content.

MIME Data consists of a file extension, a MIME type (to send to the browser),
and a set of file signatures or "magic numbers", which are the first few bytes 
of a file which give an indication of what type of file this is. This method is 
used as a quick way to detect file types without having to reading the entire 
file.

Files without signatures are treated as text types. E.G. css, js, html etc...

More file types may be added to this list.

Convention: 
File extension	MIME type	Byte signature(s) delimited by spaces

-- MIME data:
css	text/css
js	text/javascript 
txt	text/plain
html	text/html
vtt	text/vtt
csv	text/csv
svg	image/svg+xml

ico	image/vnd.microsoft.icon	\x00\x00\x01\x00
jpg	image/jpeg			\xFF\xD8\xFF\xE0  \xFF\xD8\xFF\xE1  \xFF\xD8\xFF\xEE  \xFF\xD8\xFF\xDB
jpeg	image/jepg			\xFF\xD8\xFF\xE0  \xFF\xD8\xFF\xEE
gif	image/gif			\x47\x49\x46\x38\x37\x61  \x47\x49\x46\x38\x39\x61
bmp	image/bmp			\x42\x4D
png	image/png			\x89\x50\x4E\x47\x0D\x0A\x1A\x0A
tif	image/tiff			\x49\x49\x2A\x00  \x4D\x4D\x00\x2A
tiff	image/tiff			\x49\x49\x2A\x00  \x4D\x4D\x00\x2A
webp	image/webp			\x52\x49\x46\x46  \x57\x45\x42\x50

ttf	font/ttf			\x00\x01\x00\x00\x00
otf	font/otf			\x4F\x54\x54\x4F
woff	font/woff			\x77\x4F\x46\x46
woff2	font/woff2			\x77\x4F\x46\x32

oga	audio/oga			\x4F\x67\x67\x53
mpa	audio/mpa			\xFF\xE  \xFF\xF
mp3	audio/mp3			\xFF\xFB  \xFF\xF3  \xFF\xF2  \x49\x44\x33
m4a	audio/m4a			\x00\x00\x00\x18\x66\x74\x79\x70\x4D
wav	audio/wav			\x52\x49\x46\x46  \x57\x41\x56\x45
wma	audio/x-ms-wma			\x30\x26\xB2\x75\x8E\x66\xCF\x11  \xA6\xD9\x00\xAA\x00\x62\xCE\x6C
flac	audio/flac			\x66\x4C\x61\x43\x00\x00\x00\x22
weba	audio/webm			\x1A\x45\xDF\xA3

avi	video/x-msvideo			\x52\x49\x46\x46  \x41\x56\x49\x20
mp4	video/mp4			\x00\x00\x00\x18\x66\x74\x79\x70\x4D
mpeg	video/mpeg			\xFF\xE  \xFF\xF
mkv	video/x-matroska		\x1A\x45\xDF\xA3
mov	video/quicktime			\x00\x00\x00\x14\x66\x74\x79\x70\x4D
ogg	video/ogg			\x4F\x67\x67\x53
ogv	video/ogg			\x4F\x67\x67\x53
webm	video/webm			\x1A\x45\xDF\xA3
wmv	video/x-ms-asf			\x30\x26\xB2\x75\x8E\x66\xCF\x11  \xA6\xD9\x00\xAA\x00\x62\xCE\x6C

doc	application/msword		\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1
docx	application/vnd.openxmlformats-officedocument.wordprocessingml.document		\x50\x4B\x03\x04
ppt	application/vnd.ms-powerpoint	\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1
pptx	application/vnd.openxmlformats-officedocument.presentationml.presentation	\x50\x4B\x03\x04  \x50\x4B\x07\x08
odt	application/vnd.oasis.opendocument.text		\x50\x4B\x03\x04
odp	application/vnd.oasis.opendocument.presentation	\x50\x4B\x03\x04
ods	application/vnd.oasis.opendocument.spreadsheet	\x50\x4B\x03\x04
ott	application/vnd.oasis.opendocument.text-template	\x50\x4B\x03\x04

pdf	application/pdf			\x25\x50\x44\x46\x2D
epub	application/epub+zip		\x50\x4B\x03\x04  \x50\x4B\x05\x06

zip	pplication/zip			\x50\x4B\x03\x04  \x50\x4B\x05\x06
7z	application/x-7z-compressed	\x37\x7A\xBC\xAF\x27\x1C
gz	application/gzip		\x1F\x8B
rar	application/vnd.rar		\x52\x61\x72\x21\x1A\x07
tar	application/x-tar		\x75\x73\x74\x61\x72\x00\x30\x30  \x75\x73\x74\x61\x72\x20\x20\x00
-- End mime data



The following are a set of HTTP response codes sent to the user before any 
other headers, including the preamble and content types. This response is 
required for the script to function correctly when serving web pages.

The most common type should be 200 OK to indicate the request has succeeded.
Next likely is 404 Not Found to indicate a particular resource hasn't been 
located at the address used by the visitor.

Some responses have been omitted as they should be handled at the web server 
level instead of at the Perl script, and/or they're unsuitable to implement 
here.

Convention: 
Numeric code	Text message

-- HTTP response codes:
200	OK
201	Created
202	Accepted

204	No Content
205	Reset Content
206	Partial Content

300	Multiple Choices
301	Moved Permanently
302	Found
303	See Other
304	Not Modified

400	Bad Request
401	Unauthorized

403	Denied
404	Not Found
405	Method Not Allowed
406	Not Acceptable
407	Proxy Authentication Required

409	Conflict
410	Gone
411	Length Required
412	Precondition Failed
413	Payload Too Large
414	Request-URI Too Long
415	Unsupported Media Type
416	Range Not Satisfiable

422	Unprocessable Entity

425	Too Early

429	Too Many Requests

431	Request Header Fields Too Large

500	Internal Server Error
501	Not Implemented
-- End response codes 



The following are a set of reusable HTML templates for rendering content. 
The convention for template is "tpl_label:" followed by "end_tpl", without 
quotes, where "label" is the unique identifier. Add and extend as needed.


Basic page:

tpl_page:
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>{title}</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>{body}</body>
</html>
end_tpl



Generic error message wrapper

tpl_error_page:
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>{code} - {message}</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
* {
	box-sizing: border-box
}

body {
	font: 400 1rem sans-serif; 
	line-height: 1.6; 
	color: #34495E; 
	background: #efefef 
}

h1 { 
	font-weight: 400; margin: 0; 
}

a { color: #415b76 }
a:active { color: #e74c3c }
a:hover{ color: #2c81ba }

main {
	position: absolute; 
	width: 80%; 
	top: 50%; 
	left: 50%; 
	transform: translate( -50%, -50% ) 
}
</style>
</head>
<body>
<main>
	<h1>{code} - {message}</h1>
	<p>{body}</p>
	<p><a href="/">Back</a>
</main>
</body>
</html>	

end_tpl




The following are mbedded media templates for use with uploaded files.

tpl_figure_embed:
<figure><img src="{src}" alt="{alt}"><figcaption>{caption}</figcaption></figure>
end_tpl


Embedded audio:

tpl_audio_embed:
<div class="media"><audio src="{src}" preload="none" controls></audio></div>
end_tpl


Embedded video without preview:

tpl_video_np_embed:
<div class="media">
	<video width="560" height="315" src="{src}" preload="none" 
		controls>{detail}</video>
</div>
end_tpl

Embedded video with preview:

tpl_video_embed:
<div class="media">
	<video width="560" height="315" src="{src}" preload="none" 
		poster="{preview}" controls>{detail}</video>
</div>
end_tpl


Video caption track without language:

tpl_cc_nl_embed:
<track kind="captions" src="{src}" {isdefault}>
end_tpl


Video caption with language

tpl_cc_embed:
<track label="{label}" kind="subtitles" srclang="{lang}" src="{src}" {isdefault}>
end_tpl


Media transcript block

tpl_transcript
<figure class="transcript">
	<figcaption>{title}</figcaption>
	<blockquote>{script}</blockquote>
</figure>
end_tpl



The following are third-party hosted media templates



YouTube video wrapper:

tpl_youtube:
<div class="media">
	<iframe width="560" height="315" frameborder="0" 
		sandbox="allow-same-origin allow-scripts" 
		src="https://www.youtube.com/embed/{src}?start={time}" 
		allow="encrypted-media;picture-in-picture" 
		loading="lazy" allowfullscreen></iframe>
</div>
end_tpl


Vimeo video wrapper:

tpl_vimeo:
<div class="media">
	<iframe width="560" height="315" frameborder="0" 
		sandbox="allow-same-origin allow-scripts" 
		src="https://player.vimeo.com/video/{src}" 
		allow="picture-in-picture" loading="lazy" 
		allowfullscreen></iframe>
</div>
end_tpl


Peertube video wrapper (any instance):

tpl_peertube:
<div class="media">
	<iframe width="560" height="315" frameborder="0" 
		sandbox="allow-same-origin allow-scripts" 
		src="https://{src_host}/videos/embed/{src}" 
		allow="picture-in-picture" loading="lazy" 
		allowfullscreen></iframe>
</div>
end_tpl


Internet Archive media wrapper:

tpl_archiveorg:
<div class="media">
	<iframe width="560" height="315" frameborder="0" 
		sandbox="allow-same-origin allow-scripts" 
		src="https://archive.org/embed/{src}" 
		allow="picture-in-picture" loading="lazy" 
		allowfullscreen></iframe></div>
end_tpl


LBRY/Odysee video wrapper:

tpl_lbry:
<div class="media">
	<iframe width="560" height="315" frameborder="0" 
		sandbox="allow-same-origin allow-scripts" 
		src="https://{src_host}/$/embed/{slug}/{src}" 
		allow="picture-in-picture" loading="lazy" 
		allowfullscreen></iframe>
</div>
end_tpl


Playeur/Utreon video wrapper:
tpl_playeur:
<div class="media">
	<iframe width="560" height="315" frameborder="0" 
		sandbox="allow-same-origin allow-scripts" 
		allow="encrypted-media;picture-in-picture"
		src="https://playeur.com/embed/{src}?t={time}" 
		loading="lazy" allowfullscreen></iframe>
</div>
end_tpl


__END__

BSD 2-Clause License

Copyright (c) 2024, Rustic Cyberpunk

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

