
# Fresh verison checker
package Perlite::Updater;

use strict;
use warnings;
use utf8;

use Carp;
use URI;
use IO::Socket::SSL;

use Perlite::Util qw( jsonDecode );
use Perlite::Filter qw( trim );
use Perlite::Format qw( replace );


# TODO: Set update urls and other configs
use constant {
	# Changes from last version 
	UPDATE_URL	=> '[TBD]/latest.json',
	
	# Full update log from all versions
	FULL_URL	=> '[TBD]/full.json',
	
	# "Browser" User Agent
	USER_AGENT	=> 'Perlite Update Checker'
};

sub new {
	my ( $class, $args )	= @_;
	
	if ( !defined $args->{main} ) {
		die "Main required for Updateer to continue";
	}
	
	my $self	= {
		main		=> $args->{main}
	};
	
	bless	$self, $class;
	return	$self;
}

sub formatLog {
	my ( $self, $json )	= @_;
	
	return {
		version		=> $json->{version}	// '0',
		since		=> $json->{since}	// '0',
		message		=> $json->{message}	// '',
		changelog	=> $json->{changelog}	// [],
	};
}

# Fetch update information from designated URL (TLS only)
sub checkAvailable {
	my ( $self, $url )	= @_;
	
	$url			//= UPDATE_URL;
	
	my $since		= $self->{main}::VERSION;
	my $uri			= URI->new( $url );
	
	# Request template
	my $send	= 
	replace( <DATA>, {
		path	=> $uri->path,
		host	=> $uri->host,
		since	=> $since,
		ua	=> USER_AGENT
	} );
	trim( \$send );
	
	my @request	= map{ trim( \$_ ) . "\r\n" } split( /\n/, $send );
	push( @request, "\r\n" );
	
	my $socket		= 
	IO::Socket::SSL->new(
		PeerAddr => $uri->host,
		PeerPort => '443',
		SSL_verify_mode	=> SSL_VERIFY_PEER,
	) or croak "Failed to connect to host $!, $SSL_ERROR\n";
	
	print $socket @request;
	
	my $response		= '';
	while (<$socket>) {
		$response	.= $_;
	}
	
	close( $socket );
	
	my ( $content )		= $response =~ m/\r?\n\r?\n(.*)/s;
	my $json		= jsonDecode( $content );
	
	return {} unless $json;
	$json	= $self->formatLog( $json );
	return $json;
}

# Get update or force refresh of {available} value
sub updateAvailable {
	my ( $self, $url )	= @_;
	
	$self->{available}	= $self->checkAvailable( $url );
	return $self->{available};
}

# Update request, doesn't force refresh if previously set
sub getAvailable {
	my ( $self, $url )	= @_;
	
	if ( exists( $self->{available} ) ) {
		return $self->{available};
	}
	return $self->updateAvailable( $url );
}

1;

# Request template

__DATA__

GET {path} HTTP/1.1
Host: {host}
User-Agent: {ua}
Since-Version: {since}
Cache-Control: no-cache
Pragma: no-cache
Accept: application/json;q=0.9,text/plain,text/html
Upgrade-Insecure-Requests: 1
Connection: close




