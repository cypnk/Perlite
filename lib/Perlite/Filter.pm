
# Basic filtering
package Perlite::Filter;

use strict;
use warnings;

use Unicode::Normalize;
use Encode qw( is_utf8 encode decode );
use Exporter qw( import );

our @EXPORT_OK	= 
qw( trim intRange pacify unifySpaces labelName strsize findDiffs mergeArrayUnique escapeCode );


# Trim leading and trailing space 
sub trim {
	my ( $txt ) = @_;
	return '' unless defined $txt && ref( $txt ) eq 'SCALAR';
	$$txt	=~ s/^\s+|\s+$//g;
}

# Filter number within min and max range, inclusive
sub intRange {
	my ( $val, $min, $max ) = @_;
	my $out = sprintf( "%d", "$val" );
 	
	return 
	( $out > $max ) ? $max : ( ( $out < $min ) ? $min : $out );
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

# Convert to label name with normalized and space removed string
sub labelName {
	my ( $text )		= @_;
	
	if ( !is_utf8( $text ) ) {
		$text = encode( 'UTF-8', $text );
	}
	$text	=~ s/[[:space:]]+//g;
	$text	= NFC( $text );
	$text	=~ s/[^\x00-\x7F]//g;
	
	return $text;
}

# Length of given string
sub strsize {
	my ( $str ) = @_;
	
	$str = pacify( $str );
	if ( !is_utf8( $str ) ) {
		$str = encode( 'UTF-8', $str );
	}
	return length( $str );
}

# Find differences between blocks of text
sub findDiffs {
	my ( $oblock, $eblock )	= @_;
	
	return {} unless defined( $oblock ) && !ref( $oblock );
	return {} unless defined( $eblock ) && !ref( $eblock );
	
	# Presets
	$oblock		=~ s/\r\n|\r/\n/g;
	$eblock		=~ s/\r\n|\r/\n/g;
	
	if ( $eblock eq $oblock ) {
		return { 
			total	=> 0, 
			added	=> 0, 
			deleted	=> 0, 
			changed	=> 0, 
			diffs	=> [] 
		};
	}
	
	my @original	= split /\n/, $oblock, -1;
	my @edited	= split /\n/, $eblock, -1;
	
	# Line sizes
	my $olen	= scalar( @original );
	my $elen	= scalar( @edited );
	my $max_lines	= ( $olen > $elen ) ? $olen : $elen;
	
	
	# Totals
	my $added	= 0;
	my $deleted	= 0;
	my $changed	= 0;
	
	my @diffs;
	
	for ( my $i = 0; $i < $max_lines; $i++ ) {
		# No change? Skip
		next if defined( $edited->[$i] ) && 
			defined( $original->[$i] ) && 
			$edited->[$i] eq $original->[$i];
		
		# Added lines
		if ( defined( $edited->[$i] ) && !defined( $original->[$i] ) ) {
			push( @diffs, { 
				line	=> $i, 
				change	=> "+", 
				text	=> $edited->[$i] 
			} );
			$added++;
			next;
		} 
		
		# Deleted lines
		if ( !defined( $edited->[$i] ) && defined( $original->[$i] ) ) {
			push( @diffs, { 
				line	=> $i, 
				change	=> "-", 
				text	=> $original->[$i]
			} );
			
			$deleted++;
			next;
		}
		
		# Edited lines
		push( @diffs, { 
			line	=> $i, 
			change	=> "+", 
			text	=> $edited->[$i]
		} );
		push( @diffs, { 
			line	=> $i, 
			change	=> "-", 
			text	=> $original->[$i]
		} );
		$changed++;
	}
	
	return { 
		total	=> $max_lines,
		added	=> $added, 
		deleted	=> $deleted, 
		changed	=> $changed,
		diffs	=> \@diffs 
	};
}

# Merge arrays and return unique items
sub mergeArrayUnique {
	my ( $items, $nitems ) = @_;
	
	# Check for array or return as-is
	unless ( ref( $items ) eq 'ARRAY' ) {
		return $items;
	}
	
	if ( ref( $nitems ) eq 'ARRAY' && @{$nitems} ) {
		push( @{$items}, @{$nitems} );
		
		# Filter duplicates
		my %dup;
		@{$items} = grep { !$dup{$_}++ } @{$items};
	}
	
	return $items;
}

# Format code to HTML
sub escapeCode {
	my ( $code ) = @_;
	
	return '' if !defined( $code ) || $code eq ''; 
	
	if ( !is_utf8( $code ) ) {
		$code = decode( 'UTF-8', $code );
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


1;

