
# Entitiy model
package Perlite::Models::Model;

use strict;
use warnings;

sub new { 
	my ( $class, $args )	= @_;
	if ( !defined $args->{controller} ) {
		die "Controller required for Model";
	}
	
	my $self	= {
		controller	=> $args->{controller}
	};
	
	bless	$self, $class;
	return	$self;
}

sub logError {
	my ( $self, $msg )	= @_;
	$self->{controller}->{settings}->{main}->logError( $msg );
}

sub property {
	my ( $self, $prop )	= @_;
	
	return exists( $self->{$prop} ) ? $self->{$prop} : undef;
}

1;

