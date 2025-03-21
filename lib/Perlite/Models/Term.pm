
# Naming for categorization
package Perlite::Models::Term;

use strict;
use warnings;
use utf8;

use Perlite::Util qw( mergeProperties );
use parent 'Perlite::Models::Model';

sub new {
	my ( $class, $args )	= @_;
	my $self = $class->SUPER::new( $args );
	my $_self	= {
		name	=> $args->{name}	// '',
		slug	=> $args->{slug}	// '',
	};
	
	$self	= mergeProperties( $self, $_self );
	bless $self, $class;
	return $self;
}

1;

