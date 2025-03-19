
# Content type
package Perlite::Models::NodeType;

use strict;
use warnings;

use parent 'Perlite::Models::Configurable';
sub new {
	my ( $class, $args )	= @_;
	
	my $self	= $class->SUPER::new( $args ); 
	my $_self	= {
		node_type_id	=> $args->{node_type_id},
		label		=> $args->{label},
		handler		=> $args->{handler},
		settings	=> $args->{settings} // {}
	};
	
	$self	= mergeProperites( $self, $_self );
	bless $self, $class;
	return $self;
}

1;

