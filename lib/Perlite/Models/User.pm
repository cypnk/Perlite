
# Registered User model
package Perlite::Models::User;

use strict;
use warnings;
use utf8;

use Perlite::Util qw( hashPassword verifyPassword genSalt hmacDigest );
use parent 'Perlite::Models::Configurable';

sub new {
	my ( $class, $args )	= @_;
	my $self = $class->SUPER::new( $args );
	
	$self	= {
		username	=> $args->{username}		// '';
		password_hash	=> $args->{password_hash}	// '';
		email		=> $args->{email}		// '';
	};
	
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

# Hash cleartext password and store
sub setPassword {
	my ( $self, $password )	= @_;
	
	
	# Password hashing rounds
	my $rounds	= 
	$self->{controller}->{settings}->settings( 'hash_rounds', 'int', 10000 );
	
	my $salt	= genSalt( 16 );
	
	$self->{password_hash}	= 
		hashPassword( $password, $salt, $rounds );
}

# Check against stored hash
sub passwordAuth {
	my ( $self, $password )	= @_;
	my $hash	= $self->getPasswordHash();
	if ( $hash eq '' ) {
		return 0;
	}
	return verifyPassword( $password, $hash );
}


1;

