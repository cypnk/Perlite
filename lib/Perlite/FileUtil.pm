
# File and storage helpers
package Perlite::FileUtil;

use strict;
use warnings;

use Carp;
use File::Basename qw( fileparse );
use File::Copy qw( copy move );
use File::Temp qw( tempfile tempdir );
use File::Spec::Functions qw( catfile canonpath file_name_is_absolute rel2abs );
use Fcntl qw( SEEK_SET O_WRONLY O_EXCL O_RDWR O_CREAT );
use Errno qw( EEXIST );
use Exporter qw( import );

use Perlite::Filter qw( pacify unifySpaces mergeArrayUnique );

our @EXPORT_OK	= 
qw( timestamp filterPath filterFileName storage dupRename fileLock 
	fileList fileRead fileWrite searchFiles startFlush );

# Formatted date time helper
sub timestamp {
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

# Convert to a valid file or directory path
sub filterPath {
	my ( $path, $ns ) = @_;
	
	# Define reserved characters
	my @reserved	= qw( : * ? " < > | ; );
	
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

# Convert to cross-platform safe filename
sub filterFileName {
	my ( $fname, $ns, $fnlimit ) = @_;
	my @reserved = 
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
	$fnlimit //= 255;
	return substr( $fname, 0, $fnlimit ); 
}

# Relative storage directory
sub storage {
	my ( $path, $root ) = @_;
	my $dir = pacify( $root );
	if ( $dir eq '' ) {
		croak "Storage directory is empty";
	}
	
	$dir = filterPath( $dir );
	unless ( -d $dir && -r $dir && -w $dir ) {
		croak "Storage directory is not accessible";
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
	my ( $fname, $ltype, $tries ) = @_;
	
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
	
	# Default to 4 tries
	$tries	//= 4;
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
	my ( $path, $data, $root ) = @_;
	
	$path = storage( $path, $root );
	
	# If file exists, create a backup
	if ( -e $path ) {
		my $bkp	= $path . '_backup_' . timestamp();
		copy( $path, $bkp ) or croak "Failed creating backup";
	}
	
	fileWrite( $path, $data );
}

# Send buffered output to the client and enable auto flush
sub startFlush() {
	STDOUT->flush();
	STDOUT->autoflush( 1 );
}


1;

