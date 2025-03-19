
# Message formatting, sending, and receiving
package Perlite::Reporting;

use strict;
use warnings;

use Exporter qw( import );

use Perlite::Filter qw( unifySpaces );
use Perlite::FileUtil qw( filterPath );

our @EXPORT_OK	= qw( callerTrace report cleanMsg hasErrors );


# Helper to find nested caller subroutine details for debugging, logging etc...
sub callerTrace {
	my ( $max_depth, $filter )	= @_;
	
	my @callers;
	my $depth		= 0;
	
	# Presets
	$max_depth		= 20 
		unless defined( $max_depth ) && $max_depth =~ /^\d+$/;
	
	$filter			= {} if ref( $filter ) ne 'HASH';
	$filter->{exclude}	= [] 
		unless defined( $filter->{exclude} ) && 
			ref( $filter->{exclude} ) ne 'ARRAY';
	
	while ( my $info = caller( $depth ) ) {
		last if ( $max_depth > 0 && $depth >= $max_depth );
		next if grep { $_ eq $info[0] } @{$filter->{exclude}};
		
		push( @callers, {
			pkg	=> $info[0] // 'Unknown',
			fname	=> $info[1] // 'Unknown',
			line	=> $info[2] // 'Unknown',
			func	=> $info[3] // 'Unknown',
		} );
		$depth++;
	}
	
	return @callers;
}

# Error and message report formatting helper
sub report {
	my ( $msg )	= @_;
	
	$msg		||= 'Empty message';
	$msg		= unifySpaces( $msg );
	
	my @callers	= callerTrace();
	
	my $out		= '';
	foreach my $trace ( @callers ) {
		my $pkg		= $trace->{pkg};
		my $fname	= filterPath( $trace->{fname} );
		my $func	= $trace->{func};
		my $line	= $trace->{line};
		
		$out .= "\nPackage: ${pkg}, File: ${fname}, " . 
		"Subroutine: ${func}, Line: ${line}";
	}
	
	return "${msg} ( $trace\n )";
}

# Remove sensitive data from messages
sub cleanMsg {
	my ( $self, $msg, $private ) = @_;
	
	return '' unless defined $msg;
	
	$private	= [] unless defined $private && ref $private eq 'ARRAY';
	
	my @clean	= grep { defined && $_ ne '' } @{$private};
	
	my $pat	= join( '|', map { quotemeta $_ } @clean );
	return $msg unless $pat;
	
	my $rx	= qr/(?:$pat)/i;
	my $out = $msg;
	$out =~ s/$rx/REDACTED/gi;
	
	return $out;
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

# Environment dump
sub envDump {
	print "Content-type: text/plain; charset=UTF-8\n\n";
	foreach my $var ( sort( keys( %ENV ) ) ) {
		my $val = $ENV{$var};
		$val =~ s|\n|\\n|g;
		$val =~ s|"|\\"|g;
		print "${var} = \"${val}\"\n";
	}
}

1;

