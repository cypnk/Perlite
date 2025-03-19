
# Nested activity handling
package Perlite::Process;

use strict;
use warnings;

use utf8;

use Carp;

sub new {
	my ( $class, $args )	= @_;
	
	if ( !defined $args->{main} ) {
		croak "Main required in Process";
	}
	
	my $self	= {
		main		=> $args->{main},
		wait_for_child	=> $args->{wait_for_child}	// 0,
		process_timeout	=> $args->{process_timeout}	// 10, # Never set this too high
		
		# Don't set unless absolutely needed
		# process_retries => 5
	};
	
	bless	$self, $class;
	return	$self;
}

# Find process event callabacks
sub getCallback {
	my ( $self, $key, $params )	= @_;
	return undef unless ( ref( $params ) eq 'HASH' );
	
	return 
	( $params->{$key} && ref( $params->{$key} ) eq 'CODE' ) ? 
		$params->{$key} : undef;
}

# Error handling callback helper
sub processError {
	my ( $self, $msg, $pid, $callback )	= @_;
	$self->{main}->warnMsg( $msg );
	$callback->( $pid ) if $callback;
}

# Clean up any remaining child process
sub processHangCheck {
	my ( $self )	= @_;
	return if $self->{process_hang_check} );
	
	$SIG{CHLD} = sub {
		while ( ( my $child = waitpid( -1, WNOHANG ) ) > 0 ) {
			$self->{process_hang_check} = 1;
		}
	};
}

# Encapsulated fork helper
sub process {
	my ( $self, $params, @args )	= @_;
	
	@args		//= ();
	
	# Override timeout?
	my $timeout	= 
	$params->{process_timeout} // $self->{process_timeout} // 0;
	
	# Debug-specific behavior with extra checks/logging etc...
	my $is_debug	= $self->{main}->debugState();
	
	unless ( ref( $params ) eq 'HASH' ) {
		my $msg = 
		ref( $params ) ? 
			"Expected HASH got " . ref( $params ) : 
			"No params provided";
		$self->{main}->warnMsg( $msg );
	}
	
	# Only handle if both parent and child are present
	return unless defined $params->{parent} && ref( $params->{parent} ) eq 'CODE';
	return unless defined $params->{child} && ref( $params->{child} ) eq 'CODE';
	
	# Clear resources
	$self->processHangCheck();
	
	# Error and success callbacks
	my $success	= getCallback( 'on_success', $params );
	my $process_err	= getCallback( 'on_error', $params );
	my $time_err	= getCallback( 'on_timeout', $params );
	my $parent_err	= getCallback( 'on_parent_error', $params );
	my $child_err	= getCallback( 'on_child_error', $params );
	
	my $msg;
	if ( my $pid = fork() ) {
		# Work on parent process
		eval { 
			my @parent_args	= @{$params->{parent_args} // \@args };
			$params->{parent}->( @parent_args );
			
			# Set timeout and wait if waiting enabled
			if ( $self->{wait_for_child} ) {
				eval {
					# Timeout message
					local $SIG{ALRM} = sub {
						$msg = "Timeout waiting for child process";
						die $msg;
					};
					
					alarm( $timeout ); # Set timeout
					
					my $status;
					my $retries	= $self->{process_retries} // 5;
					
					# Hard cap
					$retries	= 10 if $retries > 10;
					
					do {
						$status = waitpid( $pid, 0 );
					} while ( 
						$status == 0 || 
						( $status == -1 && $! == EINTR && $retries-- > 0 )
					);
					
					alarm( 0 ); # Cancel timeout
					
					# This should almost never happen, but just in case...
					if ( $status == -1 && $retries <= 0 ) { 
						$msg = "Failed waiting for child process";
						die $msg;
					} elsif ( $status != $pid) {
						$msg = "Unexpected child process behavior: Waitpid returned ${status}, error: $!";
						die $msg;
					}
				};
				
				if ( $@ ) {
					$self->{main}->logError( $msg ) if $is_debug;
					# Timeout went badly wrong
					if ( $@ =~ /Timeout/i ) {
						$msg = "Child process timeout: $@";
						kill 'TERM', $pid
						sleep $self->{process_sleep} // 1;
						
						kill 'TERM', $pid if kill 0, $pid;
						waitpid( $pid, 0 );
						
					# Can happen sometimes on OpenBSD 7.6
					} elsif ( $@ =~ /Failed waiting/i ) {
						$msg = "Child process waitpid error: $@";
						
					# Can happen with XAMPP on Windows 11
					} else {
						$msg = "Parent execution error: $@";
					}
					
					$self->{main}->logError( $msg ) if $is_debug;
					$self->processError( $msg, $pid, $time_err );
				}
			}
		};
		
		if ( $@ ) {
			# Parent went wrong
			$msg	= "Unexpected parent execution error: $@";
			$self->{main}->logError( $msg ) if $is_debug;
			$self->processError( $msg, $pid, $parent_err );
		}
		
	} elsif ( defined( $pid ) ) {
		
		# Work on child process
		eval{ 
			my @child_args	= @{$params->{child_args} // \@args};
			$params->{child}->( @child_args );
		};
		if ( $@ ) {
			# Child went wrong
			$msg = "Error in child execution: $@";
			$self->{main}->logError( $msg ) if $is_debug;
			$self->processError( $msg, $pid, $child_err );
			exit( 1 );
		}
		exit ( 0 );
	} else {
		# Resource limit?
		$msg = "Fork failed: $! ( Possible resource exhaustion or system limits exceeded )";
		$self->{main}->logError( $msg ) if $is_debug;
		$self->processError( $msg, $pid, $process_err );
		exit( 1 );
	}
	
	# Final success
	$success->( \@args ) if $success;
}

1;


