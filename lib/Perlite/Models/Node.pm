
# Content base
package Perlite::Models::Node;

use strict;
use warnings;

use Perlite::Util qw( mergeProperties );
use parent 'Perlite::Models::Configurable';

sub new {
	my ( $class, $args ) = @_;
	
	my $self = $class->SUPER::new( $args ); 
	my $_self	= {
		node_id		=> $args->{node_id},
		type		=> $args->{type},
		author_id	=> $args->{author_id},
		title		=> $args->{title},
		content		=> $args->{content},
		sort_order	=> $args->{sort_order} || 0,
	};
	
	$self	= mergeProperties( $self, $_self );
	bless $self, $class;
	return $self;
}

sub create {
	my ( $self )	= @_;
	unless ( $self->{node_type_id} && $self->{title} ) {
		$self->logError( "Missing required fields" );
		return 0;
	}
	
	my $id = $self->{data}->insertRow( 'nodes', {
		node_type_id	=> $self->{node_type_id},
		parent_id	=> $self->{parent_id},
		author_id	=> $self->{author_id},
		title		=> $self->{title},
		rendered	=> $self->{content} // '',
		sort_order	=> $self->{sort_order}
	} );
	
	unless ( $id ) {
		$self->logError( "Failed to create node" );
		return 0;
	}
	
	$self->{node_id} = $id;
	return $id;
}

sub update {
	my ( $self )	= @_;
	unless ( $self->{node_id} ) {
		$self->logError( "Node update() called without node_id" );
		return 0;
	}
	
	my $rows = 
	$self->{data}->updateRow( 'nodes', {
		title		=> $self->{title},
		rendered	=> $self->{content},
		sort_order	=> $self->{sort_order}
	}, {
		node_id	=> $self->{node_id}
	} );
	
	unless ( $rows ) {
		$self->logError( "Node update() called without rows updated" );
		return 0;
	}
	
	return $rows;
}


1;


