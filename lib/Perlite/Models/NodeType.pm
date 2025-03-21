
# Content type
package Perlite::Models::NodeType;

use strict;
use warnings;

use Perlite::Util qw( mergeProperties );
use parent 'Perlite::Models::Configurable';

sub new {
	my ( $class, $args )	= @_;
	
	my $self	= $class->SUPER::new( $args ); 
	my $_self	= {
		node_type_id	=> $args->{node_type_id},
		label		=> $args->{label},
		handler		=> $args->{handler},
	};
	
	$self	= mergeProperties( $self, $_self );
	bless $self, $class;
	return $self;
}

1;

