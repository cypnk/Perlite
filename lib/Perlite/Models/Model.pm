
# Entitiy model
package Perlite::Models::Model;

use strict;
use warnings;

use Carp;

sub new { 
	my ( $class, $args )	= @_;
	if ( !defined $args->{controller} ) {
		croak "Controller required for Model";
	}
	
	my $self	= {
		controller	=> $args->{controller},
		data		=> 
		$args->{controller}->{settings}->{main}->getData()
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

