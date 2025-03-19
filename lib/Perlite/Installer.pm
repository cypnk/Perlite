
# First run handler
package Perlite::Installer;

use strict;
use warnings;
use version;
use utf8;

# Modules in use
use Carp;
use IO::Handle;

sub new {
	my ( $class, $args )	= @_;
	if ( !defined $args->{main} ) {
		croak "Main required for Installer to continue";
	}
	
	my $self	= {
		# Core module 
		main		=> $args->{main},
		
		# Minimum Perl version
		perl_version	=> $args->{perl_version} // '5.32.1',
		
		# Dependencies
		deps		=> 
		@{ $args->{deps} // [ 'DBI', 'Template', 'URI', 'IO::Socket::SSL' ] },
		
		# TODO: Check database types and load DBD::SQLite or DBD::mysql
		# Right now, only SQLite is supported
		
		# Enable auto-install dependencies
		auto_deps	=> $args->{auto_deps} // 0
	};
	bless	$self, $class;
	return	$self;
}

# Check if installation was over web
sub isWeb {
	return 1 if $ENV{'GATEWAY_INTERFACE'} && $ENV{'GATEWAY_INTERFACE'} =~ /^CGI/;
	return 1 if $ENV{'MOD_PERL'};
	return 1 if $ENV{'FCGI_ROLE'};
	return 0;
}

# Status success with log output
sub success {
	my ( $self, @install_log )	= @_;
	
	if ( $self->isWeb() ) {
		print "Content-type: text/html; charset=UTF-8\n\n";
		print join( "<br />", @install_log );
	} else {
		print join( "\n", @install_log );
	}
	
	$self->{main}->logToFile( 
		$self->{main}->{install_log}, 
		@install_log 
	);
	exit 0;
}

# Status fail with log output
sub fail {
	my ( $self, @install_log )	= @_;
	
	unless ( $self->isWeb() ) {
		print "Content-type: text/plain; charset=UTF-8\n\n";
	}
	
	if ( my $pid = fork() ) {
		croak join( "\n", @install_log );
	} elsif ( defined $pid ) {
		eval {
			$self->{main}->logToFile( 
				$self->{main}->{install_log}, 
				@install_log 
			);
		};
		if ( $@ ) {
			$self->{main}->warnMsg( "Install log failed: $@" );
		}
		exit 0;
	} else {
		croak join( "\n", @install_log );
	}
}

# External module install helper
sub installModule {
	my ( $self, $module, $log_ref )	= @_;
	
	# Attempt to install if unavailable
	# WARNING: This might require more permissions to run. 
	# Any new permissions should be revoked after installation.
	eval {
		require CPAN;
		open( my $stdout, '>', \my $stdout_log ) or 
			die "Unable to open STDOUT log: $!";
		open( my $stderr, '>', \my $stderr_log ) or
			die "Unable to open STDERR log: $!";
		
		local *STDOUT = $stdout;
		local *STDERR = $stderr;
		CPAN::Shell->install( $module );
		
		close $stdout if $stdout;
		close $stderr if $stderr;
		
		push( @$log_ref, "--- --- --- CPAN Output: ${stdout_log}" );
		push( @$log_ref, "--- --- --- CPAN Error output: ${stderr_log}" );
	};
	
	if ( $@ ) {
		push( 
			@$log_ref, 
			"--- --- Module ${module} required to continue. Unable to install: $@" 
		);
		return 0;
	}
	
	eval { 
		# Test install
		require $module;
		$module->import();
	};
	
	if ( $@ ) {
		push( 
			@$log_ref, 
			"--- --- Module ${module} post-install test failed: $@" 
		);
		return 0;
	}
	
	push( @$log_ref, "--- --- Module ${module} installed." );
	return 1;
}

# Check and install external modules, if needed
sub installDeps {
	my ( $self, $log_ref )	= @_;
	my @deps	= @{$self->{deps}};
	
	push( 
		@$log_ref, 
		"Checking for required modules: " . join( ', ', @deps ) 
	);
	
	foreach my $module ( @deps ) {
		# Module test
		eval {
			require $module;
			$module->import();
		};
		
		if ( $@ ) {
			unless ( $self->{auto_deps} ) {
				push( 
					@$log_ref, 
					"--- Module ${module} is missing. Cannot continue." 
				);
				$self->fail( @$log_ref );
			}
			
			push( 
				@$log_ref, 
				"--- Module ${module} is missing. Attempting to install..." 
			);
			
			my $ok = $self->installModule( $module, $log_ref );
			unless ( $ok ) {
				# Don't continue on hard fail
				$self->fail( @$log_ref );
			}
		}
	}
}

# Compare installed Perl version with target version
sub checkPerlVersion {
	my ( $self, $log_ref )	= @_;
	
	my $perl_cur	= version->new( $^V );
	my $perl_tgt	= version->declare( $self->{perl_version} );
	
	if ( $perl_cur < $perl_tgt ) {
		push( 
			@$log_ref, 
			"Required Perl version ${perl_tgt} or newer not found. Cannot continue." 
		);
		
		# Fail early
		$self->fail( $log_ref );
	}
}

# Begin installation steps
sub runInstall {
	my ( $self, @deps )	= @_;
	
	my @install_log	= ( "Starting installation..." );
	
	$self->checkPerlVersion( \@install_log );
	$self->installDeps( \@install_log );
	
	# No errors? Continue to success
	$self->success( @install_log );
}


1;

__DATA__ 



