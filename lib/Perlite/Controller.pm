
# Event dispatcher
package Perlite::Controller;

use strict;
use warnings;

use Carp;
use Data::Dumper;

use Perlite::Util qw( rewind );
use Perlite::Filter qw( trim unifySpaces );
use Perlite::FileUtil qw( storage );

# Constructor
sub new {
	my ( $class, $args )	= @_;
	
	if ( !defined $args->{config} ) {
		croak "Configuration required for Controller";
	}
	
	my $self	= {
		settings	=> $args->{config},
		handlers	=> {},
		output		=> {}
	};
	
	bless	$self, $class;
	return	$self;
}

# Return main package parameter
sub mainProperty {
	my ( $self, $prop )	= @_;
	
	return undef unless exists( $self->{settings}->{main}->{$prop} );
	return $self->{settings}->{main}->{$prop};
}

# Return configuration package parameter
sub configProperty {
	my ( $self, $prop )	= @_;
	
	return undef unless exists( $self->{settings}->{$prop} );
	return $self->{settings}->{$prop};
}

# Ensure sent names are handler key appropriate, returns '' on failiure
sub eventName {
	my ( $self, $name )	= @_;
	return '' if !defined( $name );
	return '' if ref( $name );
	
	return lc( unifySpaces( "$name", '_' ) ) if $name =~ /.+/;
	
	return '';
}

# Append potential errors to output
sub addError {
	my ( $self, $output, $msg )	= @_;
	
	$output->{err}		||= [];
	push( @{$output->{err}}, unifySpaces( $msg ) );
	$output->{err_count}	= scalar( ${$output->{err}} );
}

# Register an event handler
sub listen {
	my ( $self, $name, $handler )	= @_;
	
	return unless defined $handler;
	
	$name	= $self->eventName( $name // '' );
	return unless $name ne '';
	
	my $is_code	= ref( $handler ) eq 'CODE';
	my $is_sub	= !ref( $handler ) && defined( \&{$handler} );
	return unless $is_sub || $is_code;
	
	# Limit handlers to package scope
	my $pkg		= __PACKAGE__;
	unless ( !$is_code && $handler !~ /^${pkg}::/ ) {
		return;
	}
	
	# Initialize event
	$self->{handlers}{$name} //= [];
	
	# Skip duplicate handlers for this event and add handler
	unless (
		grep { 
			( ref( $_ ) eq 'CODE' && $_ == $handler ) || 
			( !ref( $_ ) && $_ eq $handler ) 
		} @{$self->{handlers}{$name}}
	) {
		push( @{$self->{handlers}{$name}}, $handler);
	}
}

# Stop listening for given event
sub dismiss {
	my ( $self, $name )	= @_;
	$name	= $self->eventName( $name // '' );
	return 0 unless $name ne '';
	return 0 unless exists( $self->{handlers}{$name} );
	
	delete $self->{handlers}{$name};
	return 1;
}

# Trigger an event
sub event {
	my ( $self, $name, $params )	= @_;
	
	$name	= $self->eventName( $name // '' );
	return unless $name ne ''; # Skip invalid event call
	
	my $depth;
	for ( $depth = 0; defined caller( $depth ); $depth++ ) {
		# Deepest depth
	}
	$depth--;
	my ( $pkg, $file, $line, $callr ) = caller( $depth );
	
	# Output only accepts hash
	my $output	= $self->{output}{$name} // {};
	unless ( ref( $output ) eq 'HASH' ) {
		# Reinitialize
		$output	= {};
		$self->addError( 
			$output,
			"Output for $name before current call by $callr from " . 
			"$file on $line was not a hash"
		);
	}
	
	# No registered handlers?
	unless ( exists( $self->{handlers}{$name} ) ) {
		$self->addError( 
			$output,
			"No handlers registered during $name call by $callr " . 
			"from $file on $line"
		);
		$self->{output}{$name} = $output;
		return;
	}
	
	$params		//= {};
	
	# Validate parameters
	unless ( ref( $params ) eq 'HASH' ) {
		$self->addError(
			$output,
			"Parameters for $name call by $callr from $file " . 
			"on $line not in hash format"
		);
		$self->{output}{$name} = $output;
		return;
	}
	
	for my $handler ( @{$self->{handlers}{$name}} ) {
		my $temp;
		eval {
			# Trigger with called event name, previous output, and params
			$temp =
			( ref( $handler ) eq 'CODE' ) ? 		
				$handler->( $name, $output, $params ) // {} : 
				\&{$handler}->( $name, $output, $params ) // {};
		};
		
		if ( $@ ) {
			$self->addError( 
				$output, 
				"Error during event call $name, ending early: $@;" 
			);
			last;
		}
		
		unless ( ref( $temp ) eq 'HASH' ) {
			$self->addError( 
				$output, 
				"Output from previous handler for $name by " . 
				"$callr from $file on $line was not a hash" 
			);
			next;
		}
		
		# Merge temp with current output
		$output = { %$output, %$temp };
	}
	
	# Save current output
	$self->{output}{$name} = $output;
}

# Get any stored output from previously triggered events
sub output {
	my ( $self, $name )	= @_;
	
	# Check event registry
	return {} unless exists( $self->{handlers}{$name} );
	
	# Return any output
	return {} unless exists( $self->{output}{$name} );
}

# TEMP: Tester
sub printTime {
	my ( $self )	= @_;
	
	print "Content-type: text/html; charset=UTF-8\n\n";
	print "Hello world!\n\n";
	print "\nController: " . localtime . "\n<br />";
	my $db	= Perlite::Models::Database->new( { 
		db_file => 'main.db',
		config	=> $self->{settings}
	} );
	$db->connect();
	#my $mime = $self->{settings}->mimeList();
	
	
	print Dumper( $db );
	print strsize( "Hello World" );
	print '<br />';
}

1;
