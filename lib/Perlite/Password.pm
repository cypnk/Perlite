
# Password hashing and verification handler
package Perlite::Password;

use strict;
use warnings;
use utf8;

use Carp;
use Digest::SHA qw( sha256_hex );
use Crypt::Random qw( makerandom ); 
use Crypt::Argon2 qw( argon2id_pass argon2id_verify );

# Default settings
use constant {
	ROUNDS		= 3,		# Iterations
	COST		= '32M',	# Default cost
	
	SALT_SIZE	= 128,		# Salt bisize
	SALT_STRENGTH	= 1,		# Secure
	
	PASS_LENGTH	= 32,		# Maximum password output
	PASS_PARALLEL	= 1		# Parallelism
	
	SEPARATOR	= ':'		# Stored password component separator
};


sub new {
	my ( $class, $args )	= @_;
	
	croak "Expected a hash reference for constructor arguments" 
		unless ref( $args );
	
	my $self	= {
		rounds		=> $args->{rounds}		// ROUNDS,
		cost		=> $args->{cost}		// COST,
		
		salt_size	=> $args->{salt_size},		// SALT_SIZE,
		salt_strength	=> $args->{salt_strength},	// SALT_STRENGTH,
		
		pass_length	=> $args->{pass_length},	// PASS_LENGTH,
		pass_parallel	=> $args->{pass_parallel},	// PASS_PARALLEL,
		
		separator	=> $args->{separator}		// SEPARATOR
	};
	
	bless	$self, $class;
	return	$self;
}

# Preset signature used for password generation
sub paramRevision {
	my ( $self )	= @_;
	
	return $self->{revision} if ( $self->{revision} );
	
	my @params	= 
	qw( 
		rounds cost salt_size salt_strength pass_length pass_parallel 
	);
	
	my @values	= map { defined $self->{$_} ? $self->{$_} : '' } @params;
	
	$self->{revision}	= sha256_hex( join( '', @values ) );
	return $self->{revision};
}

# Generate random salt, if not given
sub genSalt {
	my ( $self, $salt )	= @_;
	return $salt if ( defined( $salt ) ) && $salt =~ /^[a-f0-9]+$/;
	
	my $rnd		= 
	makerandom ( 
		Size		=> $self->{salt_size}, 
		Strength	=> $self->{salt_strength} 
	); 
	
	return unpack( "H*", $rnd );
}

# Check if currently stored password needs a rehash
sub needsRehash {
	my ( $self, $stored, $sep )	= @_;
	
	$sep		//= $self->{separator};
	
	croak "Separator is undefined or invalid" 
		unless defined $sep && $sep =~ /\S/;
	
	croak "Invalid stored password format" 
		unless ( ref($stored) eq 'HASH' || $stored =~ /$sep/ );
	
	# Current parameter standard
	my $curr	= $self->paramRevision();
	
	return ref( $stored ) eq 'HASH' ? 
		( $stored->{version} ne $curr ? 1 : 0 ) : 
		( split( /$sep/, $stored )[0]  ne $curr ? 1 : 0 );
}

# Hash given password with optional parameters
sub hashPassword {
	my ( $self, $pass, $salt, $rounds, $cost, $version )	= @_;
	
	# Presets
	my $len		= $self->{pass_length};
	my $para	= $self->{pass_parallel};
	
	# Modifiable params
	$salt		= $self->genSalt( $salt );
	$version	//= $self->paramRevision();
	$cost		//= $self->{cost};
	$rounds		//= $self->{rounds};
	
	my $hashed	= 
	argon2id_pass( $pass, $salt, $rounds, $cost, $len, $para );
	
	my %output	= (
		version		=> $version,
		salt		=> $salt,
		rounds		=> $rounds,
		cost		=> $cost,
		hash		=> $hashed
	);
	return \%output;
}

# Verify stored password against sent data
sub verifyPassword {
	my ( $self, $pass, $stored, $sep )	= @_;
	
	$sep		//= $self->{separator};
	croak "Separator is undefined or invalid" 
		unless defined $sep && $sep =~ /\S/;
	
	my @parts	= split( /$sep/, $stored );
	croak "Invalid stored pasword format" if ( @parts != 5 );
	
	# Breakup components by separator
	my ( $version, $salt, $rounds, $cost, $hashed ) = @parts;
	my $is_valid	= argon2id_verify( $hashed, $pass );
	
	my %output	= (
		validation	=> $is_valid ? 1 : 0,
		pass_version	=> $version,
		current_version	=> $self->paramRevision(),
		reshash		=> $self->needsRehash( $stored, $sep )
	);
	return \%output;
}

1;

