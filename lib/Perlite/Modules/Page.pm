
# Basic content page and content type
package Perlite::Modules::Page;

use strict;
use warnings;

use Perlite::Util qw( mergeProperties );
use parent 'Perlite::Models::Node';

sub new {
	my ( $class, $args )	= @_;
	
	my $self = $class->SUPER::new( $args );
	
	bless	$self, $class;
	
	$self->registerEvents();
	return	$self;
}

sub registerEvents {
	my ( $self )	= @_;
	
	#$self->{controller}->listen( 'create_page_type', sub { $self->newPageType( @_ ) } );
	#$self->{controller}->listen( 'update_page_type', sub { $self->editPageType( @_ ) } );
	#$self->{controller}->listen( 'delete_page_type', sub { $self->deletePageType( @_ ) } );
	
	$self->{controller}->listen( 'create_page', sub { $self->newPage( @_ ) } );
	$self->{controller}->listen( 'update_page', sub { $self->editPage( @_ ) } );
	$self->{controller}->listen( 'delete_page', sub { $self->deletePage( @_ ) } );
}

# TODO
sub newPage {
	my ( $self, $params )	= @_;
	
	return 1;
}

# TODO
sub editPage {
	my ( $self, $params )	= @_;
	
	return 0 unless exists( $params->{node_id} );
	return 1;
}

# TODO
sub deletePage {
	my ( $self, $params )	= @_;
}

1;


