
# Registered User model
package Perlite::Models::User;

use strict;
use warnings;


use Digest::SHA qw( sha1_hex sha1_base64 sha256_hex sha384_hex sha512_hex hmac_sha384 );

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
	my ( $self, $hash )	= @_;
	
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

# Generate random salt up to given length
sub genSalt {
	my ( $len ) = @_;
	state @pool	= ( '.', '/', 0..9, 'a'..'z', 'A'..'Z' );
	
	return join( '', map( +@pool[rand( 64 )], 1..$len ) );
}

# Generate HMAC digest
sub hmacDigest {
	my ( $key, $data )	= @_;
	my $hmac		= hmac_sha384( $data, $key );
	
	return unpack( "H*", $hmac );
}


# Generate a hash from given password and optional salt
sub hashPassword {
	my ( $pass, $salt, $rounds ) = @_;
	
	# Generate new salt, if empty
	$salt		//= genSalt( 16 );
	
	# Crypt-friendly blocks
	my @chunks	= 
		split( /(?=(?:.{8})+\z)/s, sha512_hex( $salt . $pass ) );
	
	my $out		= '';	# Hash result
	my $key		= '';	# Digest key per block
	my $block	= '';	# Hash block
	
	for ( @chunks ) {
		# Generate digest with key from crypt
		$key	= crypt( $_, substr( sha256_hex( $_ ), 0, -2 ) );
		$block	= hmacDigest( $key, $_ );
		
		# Generate hashed block from digest
		for ( 1..$rounds ) {
			$block	= sha384_hex( $block );
		}
		
		# Add block to output
		$out		.= sha384_hex( $block );
	}
	
	return $salt . ':' . $rounds . ':' . $out;
}


# Match raw password against stored hash
sub verifyPassword {
	my ( $pass, $stored ) = @_;
	
	my ( $salt, $rounds, $spass ) = split( /:/, $stored );
	
	if ( $stored eq hashPassword( $pass, $salt, $rounds ) ) {
		return 1;
	}
	
	return 0;
}


1;

