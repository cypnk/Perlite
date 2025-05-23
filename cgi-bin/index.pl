#!/usr/bin/perl -wT

# Perl version
use 5.32.1;

package Perlite;

# Basic security
use strict;
use warnings;

# Default encoding
use utf8;

# Standard modules in use
use Carp;
use MIME::Base64;
use File::Basename;
use File::Copy;
use File::Temp qw( tempfile tempdir );
use File::Spec::Functions qw( catfile canonpath file_name_is_absolute rel2abs );
use Encode;
use Digest::SHA qw( sha1_hex sha1_base64 sha256_hex );
use Fcntl qw( SEEK_SET O_WRONLY O_EXCL O_RDWR O_CREAT );
use Errno qw( EEXIST );
use Time::HiRes ();
use Time::Piece;
use JSON qw( decode_json encode_json );

use lib '../lib';
use Perlite::Filter;
use Perlite::Util;
use Perlite::Format;
use Perlite::FileUtil;
use Perlite::Reporting;

BEGIN {
	# Remove in production
	$ENV{PERLITE_MODE}	= 'development';
}


# Default settings 

use constant {
	
	# Writable content location
	STORAGE_DIR		=> "../storage",
	
	# Uploaded file subfolder in storage
	UPLOADS			=> "uploads",
	
	# Session storage fubfolder in storage
	SESSION_DIR		=> "sessions",
	
	# Default configuration file name in storage and per-site
	CONFIG_FILE		=> "config.json",
	
	# Username and password storage file name
	USER_FILE		=> "users.txt",

	# Username and given permissions
	ROLE_FILE		=> "roles.txt"
};



# Utilities




# Get raw __DATA__ content as text
sub getRawData {
	state $data;
	
	unless ( defined $data ) {
		local $/ = undef;
		$data = <DATA>;
	}
	
	return $data;
}



# Basic filtering




# Ensure sent names are handler key appropriate, returns '' on failiure
sub eventName {
	my ( $self, $name )	= @_;
	return '' if !defined( $name );
	return '' if ref( $name );
	
	return lc( unifySpaces( "$name", '_' ) ) if $name =~ /.+/;
	
	return '';
}

# Hooks and extensions
sub hook {
	my ( $data, $out )	= @_;
	state	%handlers;
	state	%output;
	
	$out		//= 0;
	
	# Hook event name
	my $name	= eventName( $data->{event} // '' );
	return {} unless $name ne '';
	
	# Register new handler?
	if ( $data->{handler} ) {
		my $handler	= $data->{handler};
		my $is_code	= ref( $handler ) eq 'CODE';
		my $is_sub	= !ref( $handler ) && defined( \&{$handler} );
		# Check if subroutine exists and doesn't return undef
		return {} unless $is_sub || $is_code;

		# Safe handler name
		$handler	= unifySpaces( $handler ) unless $is_code;
		# Limit hook to current package scope
		my $pkg		= __PACKAGE__;
		unless ( !$is_code && $handler !~ /^${pkg}::/ ) {
			return {};
		}
		
		# Initialize event
		$handlers{$name} //= [];
		
		# Skip duplicate handlers for this event and add handler
		unless (
			grep { 
				( ref( $_ ) eq 'CODE' && $_ == $handler ) || 
				( !ref( $_ ) && $_ eq $handler ) 
			} @{$handlers{$name}}
		) {
			push( @{$handlers{$name}}, $handler );
		}
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
		my $temp;
		eval {
			# Trigger with called event name, previous output, and params
			$temp =
			( ref( $handler ) eq 'CODE' ) ? 		
				$handler->( $name, $output{$name} // {}, $params ) // {} : 
				\&{$handler}->( $name, $output{$name} // {}, $params ) // {};
		};
		
		if ( $@ ) {
			# Skip saving output
			next;
		}
		
		# Merge temp with current output
		$output{$name} = { %$output{$name}, %$temp };
	}
}

# Get allowed file extensions, content types, and file signatures ("magic numbers")
sub mimeList {
	state %mime_list	= {};
	return %mime_list if keys %mime_list;
	
	my $data	= getRawData();
	
	# Mime data block
	unless ( $data =~ /--\s*MIME\s*data\s*:\s*\n(?<mime>.*?)\n--\s*End\s*MIME\s*data\s*/msi ) {
		return {};
	}
	
	my $find = $+{mime};
	trim( \$find );
	
	while ( $find =~ /^(?<ext>\S+)\s+(?<type>\S+)\s*(?<sig>.*?)\s*$/mg ) {
		my ( $ext, $type, $sig ) = ( $+{ext}, $+{type}, $+{sig} );
		$type	//= 'application/octet-stream';
		$sig	//= '';
			
		my @sig = split( /\s+/, $sig );
		$mime_list->{$ext} = { type => $type, sig => \@sig };
	}
	
	unless ( keys %mime_list ) {
		return {};
	}
	return %mime_list;
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

# Save modified configuration data
sub saveConfig {
	my ( $name, $output, $params )	= @_;
	
	my %settings	= %{$params->{data}} // {};
	my $file	= $params->{file} // '';
	if ( !keys %settings || $file eq '' ) {
		return;
	}
	
	my $out	= encode_json( %settings );
	if ( $out ne '' ) {
		fileSave( $file, $out );
	}
}

# Load configuration by realm or core
sub config {
	my ( $realm, $override )	= @_;
	$realm			//= '';
	$override		//= '';
	
	state $saved		= 1;
	state %settings		= {};
	state %rsettings	= {};
	
	# Not overriding
	if ( $override eq '' ) {
		if ( $realm eq '' ) {
			return \%settings if keys %settings;
		} else {
			return \%rsettings if keys %rsettings;
		}
	
	# Overriding, changes haven't been saved yet
	} else {
		$saved		= 0;
	}
	
	# Default config
	my $cfile		= CONFIG_FILE;
	my $conf		= fileRead( storage( $cfile, STORAGE_DIR ) );
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
		my $rfile	= catfile( $realm, CONFIG_FILE );
		my $rconf	= fileRead( storage( $rfile, STORAGE_DIR ) );
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
		
		# Register save event at shutdown
		unless ( $saved ) {
			hook( { 
				event		=> 'perlite_shutdown', 
				handler		=> 'saveConfig',
				params		=> {
					file	=> $cfile,
					data	=> \%settings
				}
			} );
			
			hook( { 
				event		=> 'perlite_shutdown', 
				handler		=> 'saveConfig',
				params		=> {
					file	=> $rfile,
					data	=> \%rsettings
				}
			} );
			$saved = 1;
		}
		
		return \%rsettings;
	}
	
	unless ( $saved ) {
		hook( { 
			event		=> 'perlite_shutdown', 
			handler		=> 'saveConfig',
			params		=> {
				file	=> $cfile,
				data	=> \%settings
			}
		} );
		$saved = 1;
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
	my $dir = storage( catfile( 'sites', $realm ), STORAGE_DIR );
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
		DIR	=> storage( UPLOADS, STORAGE_DIR ), 
		SUFFIX	=> '.tmp' 
	);
	
	unless ( defined( $tfh ) && defined( $tfn ) ) {
		append( 
			\%err, 'formDataStream', 
			report( "Failed to create a temp file for form data" ) 
		);
		return { error => \%err };
	}
	
	# Streaming chunk size
	my $chunk_size	= setting( 'chunk_size', 'int', 65536 );
	
	# Flush frequency
	my $flush_freq	= setting( 'flush_freq', 'int', 100 );
	my $flush_count	= 0;
	
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
		
		$flush_count++;
		if ( $flush_count >= $flush_freq ) {
			$tfh->flush();
			$flush_count = 0;
		}
		
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
	
	# Flush remaining chunks, if any
	$tfh->flush() if $flush_count > 0;
	
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
	my $dir		= storage( UPLOADS, STORAGE_DIR );
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
			unless ( defined( $tfh ) && defined( $tname ) ) {
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
			
			$tfh->flush();
			close( $tfh ) or do {
				append( 
					\%err, 'formDataSegment', 
					report( "Error closing temporary file: ${tname}" ) 
				);
				return { error => \%err };
			};
			
			# Special case if file was moved/deleted mid-operation
			unless ( -e $tname ) {
				append( 
					\%err, 'formDataSegment', 
					report( "Temporary file was moved, deleted, or quarantined: ${tname}" ) 
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
	
	my $state		= formDataStream( $clen );
	if ( hasErrors( %{$state} ) ) {
		%err = %{$state->{error}};
		# Merge stream errors
		append( 
			\%err, 'formData', 
			report( "Error saving form data stream" )
		);
		
		return { fields => [], files => [], error => \%err };
	}
	
	my %fields	= ();
	my @uploads	= [];
	
	# Process the file content in chunks
	my $buffer	= '';
	my $stream	= %{$state->{stream}};
	while ( my $line = <$stream> ) {
		$buffer .= $line;

		# Once a boundary is reached, process the segment
		if ( $buffer =~ /--\Q$boundary\E(?!-)/ ) {
			my $segment	= 
			formDataSegment( $buffer, $boundary, \%fields, \@uploads );
			
			if ( hasErrors( %{$segment} ) ) {
				%err = %{$segment->{error}};
				append( 
					\%err, 'formData', 
					report( "Form data stream failed" )
				);
				
				# Cleanup form data stream
				close( %{$state->{stream}} );
				unlink( %{$state->{name}} );
				return { fields => [], files => [], error => \%err };
			}
			
			# Reset
			$buffer = '';  
		}
	}
	
	# Cleanup form data stream
	close( %{$state->{stream}} );
	unlink( %{$state->{name}} );
	
	$data{'fields'}	= \%fields;
	$data{'files'}	= \@uploads;
	
	return \%data;
}

# Verify sent form data with nonce and CAPTCHA
sub validateCaptcha {
	my ( $snonce )	= @_;
	
	my $data	= formData();
	unless ( hasErrors( $data ) ) {
		return 0;
	}
	
	my %fields	= %{$data->{fields}} // {};
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
	
	my $sfile	= storage( catfile( SESSION_DIR, $id ), STORAGE_DIR );
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
	
	my $sfile	= storage( catfile( SESSION_DIR, $id ), STORAGE_DIR );
	if ( -f $sfile ) {
		unlink ( $sfile );
	}
}

# Garbage collection
sub sessionGC {
	my $sdir	= storage( SESSION_DIR, STORAGE_DIR );
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
	
	my $sdir	= storage( SESSION_DIR, STORAGE_DIR );
	unless ( -d $sdir ) {
		mkdir( $sdir, 0644 );
	}
	
	my $sfile	= storage( catfile( SESSION_DIR, sessionID() ), STORAGE_DIR );
	fileWrite( $sfile, encode_json( \%data ) );
	
	$written = 1;
}

# Cleanup
END {
	sessionWriteClose();
}




# Response




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
	my $tpl		= storage( catfile( 'sites', $realm, 'errors', "$code.html" ), STORAGE_DIR );
	my $ctpl	= storage( catfile( 'errors', "$code.html" ), STORAGE_DIR );
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
	
	startFlush();
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
	
	startFlush();
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
	
	foreach my $track ( @subs ) {
		my %data	= {};
		my $len		= scalar( $track );
		
		# Only a track
		if ( $len == 1 ) {
			%data	= (
				src		=> @$track[0],
				isdefault	=> ''
			);
			
			$out	.= 
			replace( template( 'tpl_cc_nl_embed' ), %data );
			next;
		}
		
		# Not a language, but is default
		if ( $len == 2 && lc( @$track[1] ) eq 'default' ) {
			%data	= (
				src		=> @$track[0],
				isdefault	=> 'default'
			);
			
			$out	.= 
			replace( template( 'tpl_cc_nl_embed' ), %data );
			next;
		
		# Language, but not default
		} elsif ( $len == 2 ) {
			%data	= (
				src		=> @$track[0],
				lang		=> @$track[1],
				isdefault	=> ''
			);
			
			$out	.= 
			replace( template( 'tpl_cc_embed' ), %data );
			next;
		}
		
		# Language and is default
		%data	= (
			src		=> @$track[0],
			lang		=> @$track[1],
			isdefault	=> 'default'
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
	
	if ( $idx < $total ) {
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




# Find password for an existing user
sub getPassword {
	my ( $user, $realm ) = @_;
	
	my $pass = '';
	
	my $file = storage( catfile( $realm, USER_FILE ), STORAGE_DIR );
	
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
	
	my $ifile	= storage( catfile( $realm, USER_FILE ), STORAGE_DIR );
	
	# Try to get a lock for this user file
	fileLock( $ifile, 1 ) or exit 1;
	
	# No user file for this realm? Create it
	if ( ! -f $ifile ) {
		open( INF, '>:encoding(UTF-8)', $ifile ) or exit 1;
		close( INF );
	}
	
	open( INF, '<:encoding(UTF-8)', $ifile ) or exit 1;
	
	my $ofile	= storage( catfile( $realm, USER_FILE . '.new' ), STORAGE_DIR );
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
	my ( $name, $output, $params )	= @_;
	
	# $name, $output{$name} // {}, $params
	
	# URL routing placeholders
	state %default_markers = (
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

	my %request	= getRequest();
	my $verb	= $request{'verb'};
	
	my %paths	= $params{paths} // %path_map;
	
	# Unkown request method? 
	sendOptions( 1 ) unless exists $paths{$verb};
	
	my $realm	= $request{'realm'};
	my $url		= $request{'url'};
	
	$url		= unifySpaces( $url );
	
	# Trim leading backslashes and escape any in the middle
	$url		=~ s/\/$//;
	$url		=~ s/\\/\\\\/g;
	
	# Custom URL markers
	my %markers	= setting( 'route_markers', 'hash', \%default_markers );
	
	# Begin router
	foreach my $route ( @{$paths{$verb}} ) {
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
			my %matches	= %+;
			if ( defined( &{$handler} ) ) {
				# TODO: Convert handlers to hook events
				&{$handler}( $realm, $verb, %matches );
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
		catfile( 'sites', $realm, 'static', $tree, $file ), 
		STORAGE_DIR 
	);
	
	if ( ! -f $loc ) {
		# Fallback to uploads path
		$loc = 
		storage( 
			catfile( 'sites', $realm, UPLOADS, $tree, $file ), 
			STORAGE_DIR 
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
	
	
	my $tpl = storage( catfile( 'sites', $realm, 'pages', 'home.html' ), STORAGE_DIR );
	
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

