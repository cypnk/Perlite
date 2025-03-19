
# Main configuration settings
package Perlite::Config;

use strict;
use warnings;

use Perlite::Util qw( rewind );
use Perlite::Filter qw( trim unifySpaces strsize );

sub new { 
	my ( $class, $args )	= @_;
	
	if ( !defined $args->{main} ) {
		die "Main required in Config";
	}
	
	my $self	= {
		main	=> $args->{main}
	};
	
	bless	$self, $class;
	return	$self;
}

sub getRawData() {
	my $raw		= rewind( *DATA );
	unless ( defined( $raw ) ) {
		return undef;
	}
	my $data	= join( '', <$raw> );
	unless ( $data ) {
		return undef;
	}
	
	return $data;
}

# Get allowed file extensions, content types, and file signatures ("magic numbers")
sub mimeList { 
	my ( $self )	= @_;
	
	$self->{mime_list}	//= {};
	return $self->{mime_list} if keys %{$self->{mime_list}};
	
	my $data		= getRawData();
	unless ( $data ) {
		return {};
	}
	
	my $pattern		= qr/
		^--\s*MIME\s*data\s*:\s*\n	# MIME list block start
			(?<mime>.*?)		# MIME items
		\n--\s*End\s*MIME\s*data\s*	# End MIME data 
	/ixsm;
	
	# Mime data block
	unless ( $data =~ /$pattern/g ) {
		return {};
	}
	
	my $find = $+{mime};
	trim( \$find );
	
	while ( $find =~ /^(?<ext>\S+)\s+(?<type>\S+)\s*(?<sig>.*?)\s*$/mg ) {
		my ( $ext, $type, $sig ) = ( $+{ext}, $+{type}, $+{sig} );
		$type	//= 'application/octet-stream';
		$sig	//= '';
			
		my @sig = split( /\s+/, $sig );
		$self->{mime_list}->{$ext} = { type => $type, sig => \@sig };
	}
	
	unless ( keys %{ $self->{mime_list} }) {
		return {};
	}
	return $self->{mime_list};
}

# HTTP Status codes and associated text
sub httpStatusList {
	my ( $self )	= @_;
	
	$self->{http_codes}	//= {};
	return $self->{http_codes} if keys %{$self->{http_codes}};
	
	my $data		= getRawData();
	unless ( $data ) {
		return {};
	}
	
	my $pattern		= qr/
		^--\s*HTTP\s*response\s*codes:\s*\n	# HTTP codes start
		(?<codes>.*?)				# Code list
		\n--\s*End\s*response\s*codes\s*	# End codes
	/ixsm;
	
	unless ( $data =~ /$pattern/g ) {
		return {};
	}
	my $find = $+{codes};
	trim( \$find );
		
	while ( $find =~ /^(?<code>\S+)\s+(?<message>.*?)\s*$/mg ) {
		$self->{http_codes}->{$+{code}}	= $+{message};
	}
	unless ( keys %{ $self->{http_codes} }) {
		return {};
	}
	return $self->{http_codes};
}


1;

__DATA__



Configuration and lists:
The following is a set of settings used to serve content.

MIME Data consists of a file extension, a MIME type (to send to the browser),
and a set of file signatures or "magic numbers", which are the first few bytes 
of a file which give an indication of what type of file this is. This method is 
used as a quick way to detect file types without having to reading the entire 
file.

Files without signatures are treated as text types. E.G. css, js, html etc...

More file types may be added to this list.

Convention: 
File extension	MIME type	Byte signature(s) delimited by spaces

-- MIME data:
css	text/css
js	text/javascript 
txt	text/plain
html	text/html
vtt	text/vtt
csv	text/csv
svg	image/svg+xml

ico	image/vnd.microsoft.icon	\x00\x00\x01\x00
jpg	image/jpeg			\xFF\xD8\xFF\xE0  \xFF\xD8\xFF\xE1  \xFF\xD8\xFF\xEE  \xFF\xD8\xFF\xDB
jpeg	image/jepg			\xFF\xD8\xFF\xE0  \xFF\xD8\xFF\xEE
gif	image/gif			\x47\x49\x46\x38\x37\x61  \x47\x49\x46\x38\x39\x61
bmp	image/bmp			\x42\x4D
png	image/png			\x89\x50\x4E\x47\x0D\x0A\x1A\x0A
tif	image/tiff			\x49\x49\x2A\x00  \x4D\x4D\x00\x2A
tiff	image/tiff			\x49\x49\x2A\x00  \x4D\x4D\x00\x2A
webp	image/webp			\x52\x49\x46\x46  \x57\x45\x42\x50

ttf	font/ttf			\x00\x01\x00\x00\x00
otf	font/otf			\x4F\x54\x54\x4F
woff	font/woff			\x77\x4F\x46\x46
woff2	font/woff2			\x77\x4F\x46\x32

oga	audio/oga			\x4F\x67\x67\x53
mpa	audio/mpa			\xFF\xE  \xFF\xF
mp3	audio/mp3			\xFF\xFB  \xFF\xF3  \xFF\xF2  \x49\x44\x33
m4a	audio/m4a			\x00\x00\x00\x18\x66\x74\x79\x70\x4D
wav	audio/wav			\x52\x49\x46\x46  \x57\x41\x56\x45
wma	audio/x-ms-wma			\x30\x26\xB2\x75\x8E\x66\xCF\x11  \xA6\xD9\x00\xAA\x00\x62\xCE\x6C
flac	audio/flac			\x66\x4C\x61\x43\x00\x00\x00\x22
weba	audio/webm			\x1A\x45\xDF\xA3

avi	video/x-msvideo			\x52\x49\x46\x46  \x41\x56\x49\x20
mp4	video/mp4			\x00\x00\x00\x18\x66\x74\x79\x70\x4D
mpeg	video/mpeg			\xFF\xE  \xFF\xF
mkv	video/x-matroska		\x1A\x45\xDF\xA3
mov	video/quicktime			\x00\x00\x00\x14\x66\x74\x79\x70\x4D
ogg	video/ogg			\x4F\x67\x67\x53
ogv	video/ogg			\x4F\x67\x67\x53
webm	video/webm			\x1A\x45\xDF\xA3
wmv	video/x-ms-asf			\x30\x26\xB2\x75\x8E\x66\xCF\x11  \xA6\xD9\x00\xAA\x00\x62\xCE\x6C

doc	application/msword		\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1
docx	application/vnd.openxmlformats-officedocument.wordprocessingml.document		\x50\x4B\x03\x04
ppt	application/vnd.ms-powerpoint	\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1
pptx	application/vnd.openxmlformats-officedocument.presentationml.presentation	\x50\x4B\x03\x04  \x50\x4B\x07\x08
odt	application/vnd.oasis.opendocument.text		\x50\x4B\x03\x04
odp	application/vnd.oasis.opendocument.presentation	\x50\x4B\x03\x04
ods	application/vnd.oasis.opendocument.spreadsheet	\x50\x4B\x03\x04
ott	application/vnd.oasis.opendocument.text-template	\x50\x4B\x03\x04

pdf	application/pdf			\x25\x50\x44\x46\x2D
epub	application/epub+zip		\x50\x4B\x03\x04  \x50\x4B\x05\x06

zip	pplication/zip			\x50\x4B\x03\x04  \x50\x4B\x05\x06
7z	application/x-7z-compressed	\x37\x7A\xBC\xAF\x27\x1C
gz	application/gzip		\x1F\x8B
rar	application/vnd.rar		\x52\x61\x72\x21\x1A\x07
tar	application/x-tar		\x75\x73\x74\x61\x72\x00\x30\x30  \x75\x73\x74\x61\x72\x20\x20\x00
-- End mime data



The following are a set of HTTP response codes sent to the user before any 
other headers, including the preamble and content types. This response is 
required for the script to function correctly when serving web pages.

The most common type should be 200 OK to indicate the request has succeeded.
Next likely is 404 Not Found to indicate a particular resource hasn't been 
located at the address used by the visitor.

Some responses have been omitted as they should be handled at the web server 
level instead of at the Perl script, and/or they're unsuitable to implement 
here.

Convention: 
Numeric code	Text message

-- HTTP response codes:
200	OK
201	Created
202	Accepted

204	No Content
205	Reset Content
206	Partial Content

300	Multiple Choices
301	Moved Permanently
302	Found
303	See Other
304	Not Modified

400	Bad Request
401	Unauthorized

403	Denied
404	Not Found
405	Method Not Allowed
406	Not Acceptable
407	Proxy Authentication Required

409	Conflict
410	Gone
411	Length Required
412	Precondition Failed
413	Payload Too Large
414	Request-URI Too Long
415	Unsupported Media Type
416	Range Not Satisfiable

422	Unprocessable Entity

425	Too Early

429	Too Many Requests

431	Request Header Fields Too Large

500	Internal Server Error
501	Not Implemented
-- End response codes 

