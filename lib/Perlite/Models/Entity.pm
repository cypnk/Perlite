
# Common data entity
package Perlite::Models::Entity;

use strict;
use warnings;

use Perlite::Util qw( mergeProperties );
use parent 'Perlite::Models::Model';

sub new { 
	my ( $class, $args )	= @_;
	my $self = $class->SUPER::new( $args );
	my $_self	= {
		uuid		=> $args->{uuid}	// '';
		parent_id	=> $args->{parent_id}	// 0,
		created		=> $args->{created}	// '';
		updated		=> $args->{updated}	// '';
	};
	
	$self	= mergeProperties( $self, $_self );
	bless	$self, $class;
	return	$self;
}

1;

