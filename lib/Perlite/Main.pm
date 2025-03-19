
# Core package
package Perlite::Main;

# Basic security
use strict;
use warnings;

# Default encoding
use utf8;

# Modules in use
use Carp;
use File::Spec::Functions qw( catfile );

use Perlite::Config;
use Perlite::Controller;
use Perlite::Filter qw( unifySpaces );
use Perlite::FileUtil qw( storage filterPath );
use Perlite::Reporting qw( callerTrace report hasErrors )

# Current Perlite version
our $VERSION	= "v0.0.1_1";

sub new { 
	my ( $class, $args )	= @_;
	
	# Default to 'data' outside lib folder
	my $path	= $args->{storage_dir} // '../../../storage';
	
	# Filter and parse storage dir
	$path		= storage( '/', $path );
	
	# Default parameters ( core folders and files )
	my $self	= {
		storage_dir	=> $path,
		theme_dir	=> catfile( $path, ( $args->{theme_dir} // 'themes' ) ),
		upload_dir	=> catfile( $path, ( $args->{upload_dir} // 'uploads' ) ),
		
		# Leaving the following as written is storngly recommended
		config_file	=> catfile( $path, ( $args->{config_file} // 'config.json' ) ),
		error_log	=> catfile( $path, ( $args->{error_log} // 'errors.log' ) ),
		notice_log	=> catfile( $path, ( $args->{notice_log} // 'notices.log' ) ),
		install_log	=> catfile( $path, ( $args->{install_log} // 'install.log' ) ),
	};
	
	bless	$self, $class;
	return	$self;
}

# Get globally writable directory
sub getStorageDir {
	my ( $self )	= @_;
	return $self->{storage_dir};
}

# Theme storage directory, usually inside storage
sub getThemeDir {
	my ( $self )	= @_;
	return $self->{theme_dir};
}

# Get main configuration file
sub getConfigFile {
	my ( $self )	= @_;
	return $self->{config_file};
}

# Get configuration handler class
sub getConfig {
	my ( $self )	= @_;
	if ( exists( $self->{settings} ) ) {
		return $self->{settings};
	}
	
	$self->{settings} = Perlite::Config->new( { main => $self } );
	return $self->{settings};
}

sub getData {
	my ( $self )	= @_;
	if ( exists( $self->{data} ) ) {
		return $self->{data};
	}
	
	$self->{data}	= 
	Perlite::Models::Database->new( { config => $self->getConfig() } );
	return $self->{data};
}

# Core event dispatcher
sub getController {
	my ( $self )	= @_;
	if ( exists( $self->{controller} ) ) {
		return $self->{controller};
	}
		
	$self->{controller} = 
	Perlite::Controller->new( { config => $self->getConfig() } );
	return $self->{controller};
}

# Used for extra information shown to the user
sub debugState {
	my ( $self )	= @_;
	unless( defined( $self->{is_debug} ) ) {
		$self->{is_debug} = 
		!!( defined( $ENV{PERLITE_MODE} ) && 
			$ENV{PERLITE_MODE} eq 'development' );
	}
	
	return $self->{is_debug};
}

# Format and store error
sub logError {
	my ( $self, $msg, $private ) = @_;
	
	return unless defined $msg;
	
	$self->{err}	//= [];
	
	# Cap messages
	splice(
		@{$self->{err}}, 0, @{$self->{err}} - 255
	) if @{$self->{err}} > 255;
	
	my $stamp	= localtime();
	push( @{$self->{err}}, "[$stamp] " . cleanMsg( $msg, $private ) );
}

# Store messages in given log file
sub logToFile {
	my ( $self, $log, $messages )	= @_;
	return unless $log;
	return unless ref $messages eq 'ARRAY';
	
	my $is_debug = $self->debugState();
	my $lfh;
	eval {
		open ( $lfh, '>>:encoding(UTF-8)', $log ) or 
			die "Cannot open log file";
	};
	if ( $@ ) {
		unless( $is_debug ) {
			carp "Error during file log: $@";
			return;
		}
		warn "Error writing to log file";
		return;
	}
	
	return unless $lfh;
	foreach my $msg ( @$messages ) {
		print $lfh "$msg\n\n";
	}
	close( $lfh ) or do {
		unless( $is_debug ) {
			carp "Failed to close log file $!";
			return;
		}
		warn "Failed to close log file";
	}
}

# Store and show warning messages safely
sub warnMsg {
	my ( $self, $msg, $is_debug )	= @_;
	
	$is_debug	//= $self->debugState();
	my $debug	= $is_debug ? "ON" : "OFF";
	my $send	= report( $msg // 'Empty message' );
	$self->logError( 
		"WARNING with debug: ${debug}: $send" 
	);
	
	unless( $is_debug ) {
		warn "A warning occurred";
		return;
	}
	
	# Full display
	carp $send;
}

# Store and show die messages safely
sub dieMsg {
	my ( $self, $msg, $is_debug )	= @_;
	
	$is_debug	//= $self->debugState();
	my $debug	= $is_debug ? "ON" : "OFF";
	my $send	= report( $msg // 'Empty message' );
	$self->logError( 
		"ERROR with debug: ${debug}: $send" 
	);
	
	die "An error occurred" unless $is_debug;
	
	# Full display
	croak $send;
}

# Send compiled errors to log file
sub logErrorsToFile {
	my ( $self )	= @_;
	return unless defined $self->{err} && ref $self->{err} eq 'ARRAY';
	return unless @{$self->{err}} && $self->{error_log};
	
	my $log		= $self->{error_log};
	my $is_debug	= $self->debugState();
	
	eval { $self->logToFile( $log, $self->{err} ) };
	if ( $@ ) {
		unless( $is_debug ) {
			carp "Failed to log errors: $@";
			return;
		}
		warn "Failed to log errors";
	}
}

# Send compiled messages to log file
sub logMessagesToFile {
	my ( $self )	= @_;
	return unless defined $self->{notes} && ref $self->{notes} eq 'ARRAY';
	return unless @{$self->{notes}} && $self->{notice_log};
	
	my $log		= $self->{notice_log};
	my $is_debug	= $self->debugState();
	
	eval { $self->logToFile( $log, $self->{notices} ) };
	if ( $@ ) {
		unless( $is_debug ) {
			carp "Failed to log notices: $@";
			return;
		}
		warn "Failed to log notices";
	}
}

# Last call to backup any stored messages
sub DESTROY {
	my ( $self )	= @_;
	return unless $self && ref( $self ) eq 'HASH';
	return unless defined $self->{config} && ref $self->{config} eq 'HASH';
	$self->logErrorsToFile();
	$self->logNoticesToFile();
}

1;


