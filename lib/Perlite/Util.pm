
# Utilities
package Perlite::Util;

use strict;
use warnings;

use Encode qw( is_utf8 encode decode_utf8 );
use JSON qw( decode_json encode_json );
use Time::HiRes ();
use Time::Piece;
use Digest::SHA qw( hmac_sha384 );
use Exporter qw( import );

use Perlite::Filter qw( trim pacify );

our @EXPORT_OK	= 
qw( dateRfc textStartsWith utfDecode jsonDecode verifyDate append rewind 
	mergeProperties genSalt hmacDigest );

# Password salt character pool
my @salt_pool	= ( '.', '/', 0..9, 'a'..'z', 'A'..'Z' );

# Number of days in a month (non-leap)
my @month_days	= ( 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 );

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

# Decode URL encoded strings
sub utfDecode {
	my ( $term ) = @_;
	return '' if !defined( $term ) || $term eq '';
	
	$term	= pacify( $term );
	$term	=~ s/\.{2,}/\./g;
	$term	=~ s/\+/ /g;
	$term	=~ s/\%([\da-fA-F]{2})/chr(hex($1))/ge;
	
	if ( is_utf8( $term ) ) {
		$term	= decode_utf8( $term );
	}
	
	trim( \$term );
	return $term;
}

# Safely decode JSON to hash
sub jsonDecode {
	my ( $text )	= @_;
	return {} if !defined( $text ) || $text eq '';
	
	# Already a hash?
	if ( ref( $text ) eq 'HASH' ) {
		return $text;
	}
	return {} if length( $text ) < 2;
	
	$text	= pacify( $text );
	if ( !is_utf8( $text ) ) {
		$text	= encode( 'UTF-8', $text );
	}
	
	my $out;
	eval {
		$out = decode_json( $text );
	};
	
	return {} if ( $@ );
	return $out;
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
	$month_days[1]	= 29 if $month == 2 && $is_leap;
	
	# Maximum day for given month
	return 0 if $day > $month_days[$month - 1];
	
	return 1;
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
			scalar( keys %{ $ref->{$key} } ) + 1 
		} = $msg;
		return;
	}
	$ref->{$key} = { 1 => $msg };
}

# Rewind helper for E.G. __DATA__ content
sub rewind {
	my ( $data )	= @_;
	return () unless $data;
	seek( $data, 0, 0 );
	
	return $data;
}

sub mergeProperties {
	my ( $parent_props, $child_props ) = @_;
	foreach my $key ( keys %$child_props ) {
		if ( 
			ref( $child_props->{$key} ) eq 'HASH' && 
			ref( $parent_props->{$key} ) eq 'HASH'
		) {
			$parent_props->{$key}	= 
				mergeProperties( 
					$parent_props->{$key}, 
					$child_props->{$key}
				);
		} else {
			$parent_props->{$key} = $child_props->{$key};
		}
		
		return $parent_props;
	}
}


# Generate random salt up to given length
sub genSalt {
	my ( $len ) = @_;
	return join( '', map( +@salt_pool[rand( 64 )], 1..$len ) );
}

# Generate HMAC digest
sub hmacDigest {
	my ( $key, $data )	= @_;
	my $hmac		= hmac_sha384( $data, $key );
	
	return unpack( "H*", $hmac );
}

1; 


