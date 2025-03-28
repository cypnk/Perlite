
# Registered User model
package Perlite::Models::User;

use strict;
use warnings;
use utf8;

use Perlite::Util qw( hashPassword verifyPassword genSalt hmacDigest mergeProperties );
use parent 'Perlite::Models::Configurable';

sub new {
	my ( $class, $args )	= @_;
	my $self = $class->SUPER::new( $args );
	
	my $_self	= {
		username	=> $args->{username}		// '';
		password_hash	=> $args->{password_hash}	// '';
		email		=> $args->{email}		// '';
	};
	
	$self	= mergeProperties( $self, $_self );
	bless	$self, $class;
	return	$self;
}

sub getUsername {
	my ( $self )	= @_;
	return $self->{username};
}

sub setUsername {
	my ( $self, $username )	= @_;
	$self->{username}	= $username;
}

sub getEmail {
	my ( $self )	= @_;
	return $self->{email};
}

sub setEmail {
	my ( $self, $email )	= @_;
	$self->{email}		= $email;
}

sub getPasswordHash {
	my ( $self )	= @_;
	
	return $self->{password_hash} // '';
}

1;

