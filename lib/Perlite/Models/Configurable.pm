
# Settings enabled model
package Perlite::Models::Configurable;

use strict;
use warnings;

use Perlite::Util qw( mergeProperties );
use parent 'Perlite::Models::Entity';


sub new { 
	my ( $class, %args )	= @_;
	my $self = $class->SUPER::new( %args );
	
	my $_self	= {
		settings_id		=> $args{setting_id}		// 0;
		
		# TODO: Transform text to hash
		settings		=> $args{settings}		// '';
		settings_override	=> $args{settings_override}	// '';
	};
	
	$self	= mergeProperites( $self, $_self );
	bless	$self, $class;
	return	$self;
}


1;

