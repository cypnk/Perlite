
# Category or section
package Perlite::Models::Taxonomy;

use strict;
use warnings;
use utf8;

use Perlite::Util qw( mergeProperties );
use parent 'Perlite::Models::Configurable';

sub new {
	my ( $class, $args )	= @_;
	my $self = $class->SUPER::new( $args );
	my $_self	= {
		term_id		=> $args->{term_id}	// '',
		node_count	=> $args->{node_count}	// 0,
	};
	
	$self	= mergeProperties( $self, $_self );
	bless $self, $class;
	return $self;
}

1;

