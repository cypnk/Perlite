
# HTML Content document
package Perlite::HtmlDocument;

use strict;
use warnings;

use Perlite::Util qw( jsonDecode rewind utfDecode );
use Perlite::Filter qw( trim unifySpaces escapeCode );
use Perlite::Format qw( replace markeParagraphs );

sub new { 
	my ( $class, $args )	= @_;
	
	my $tags;
	# Custom or load default
	if ( defined( $args->{whitelist} ) ) {
		$tags		= $args->{whitelist}
	} else {
		my $raw	= rewind( *DATA );
		$tags	= join( '', <$raw> );
	}
	
	my $self	= {
		whitelist	=> jsonDecode( $tags ),
		max_depth	=> $args->{max_depth} // 20		# Maximum tree depth
	};
	
	bless	$self, $class;
	return	$self;
}

# Intercept HTML tag attribute(s)
sub parseAttributes {
	my ( $self, $params )	= @_;
	my %attrs;
	
	while ( $params =~ m/(\w+)\s*=\s*["']([^"']*)["']/g ) {
		$attrs{$1} = $2;
	}
	
	return \%attrs;
}

# Check if given tag matches limited set of self-closing tags
sub isSelfClosing {
	my ( $self, $tag )	= @_;
	
	# Limited set of self-closing tags
	state %closing = 
	map { 
		$_ => 1 
	} qw( area base br col embed hr img input link meta param source track wbr );
	
	return 0 unless exists( $closing{$tag} );
	return 1;
}

# Load given HTML block into a nested hash
sub parseHTML {
	my ( $self, $html, $depth ) = @_;
	
	$depth	//= $self->{max_depth} // 20;
	
	my $tree = {};
	if ( $depth < 0 ) {
		return $tree;
	}
	$depth--;
	
	my $tag_regex = qr{
		<(\w+)						# Capture opening tag and name
		(						# Start of attributes group
			(?:\s+\w+\s*=\s*["'][^"']*["'])*	# Match key="value" or key='value'
		)						# End of attributes group
		\s*/?>						# Match optional self-closing slash
		|						# OR
		<(\w+)						# Capture opening tag name for non-self-closing tags
		(						# Repeat start of attributes group
			(?:\s+\w+\s*=\s*["'][^"']*["'])*	# Match again key="value" or key='value'
		)						# End of attributes group
		>						# Match the closing bracket
		(.*?)						# Capture content inside the tags (non-greedy)
		</\3>						# Match the closing tag, ref third capture group
	}gsx;

	while ( $html =~ $tag_regex ) {
		if ( defined $1 && $this->isSelfClosing( $1 ) ) {
			my $tag		= $1;
			my $attr	= unifySpaces( $2 );
			
			$tree->{$tag} = {
				attributes => $self->parseAttributes( $attr ),
				content    => undef
			};
		} elsif ( defined $3 ) {
			my $tag		= $3;
			my $attr	= unifySpaces( $4 );
			my $content	= $5;
			
			trim( \$content );
			
			# Escape and save any nested content if nesting isn't allowed 
			if ( $self->{whitelist}{$tag}{no_nest} // 0 ) {
				$tree->{$tag} = {
					attributes	=> $self->parseAttributes( $attr ),
					content		=> escapeCode( $content )
				};
				next;
			}
			
			# Move on to nested content
			$tree->{$tag} = {
				attributes => $self->parseAttributes( $attr ),
				content    => 
					$content =~ /</ ? 
					$self->parseHTML( $content, $depth ) : $content
			};
		}
	}
	
	return $tree;
}

# Sanitize tag attributes against whitelist
sub filterAttribute {
	my ( $self, $tag, $attr_name, $data )	= @_;
	if ( $data eq '' ) {
		return '';
	}
	
	# URI types get special treatment
	if ( 
		grep{ $_ eq $attr_name } 
			@{$self->{whitelist}{$tag}{attributes}{uri_attr} // ()} 
	) {
		$data	= utfDecode( $data );
		
		# Strip tags
		$data	=~ s/<.*?>//g;
		$data	= unifySpaces( $data );
		
		# Javascript etc...
		$data	=~ s/^javascript://i;
		
		return trim( \$data );
	}
	
	# Entities for everything else
	return escapeCode( $data );
}

# Raw collapse of HTML node to text
sub flattenNode {
	my ( $self, $node )	= @_;
	my $out	= '';
	
	foreach my $tag ( keys %{$node} ) {
		my $attr = '';
		foreach my $attr_name ( keys %{$node->{$tag}{attributes}} ) {
			my $data = $node->{$tag}{attributes}{$attr_name} // '';
			
			$attr .= 
			sprintf( ' %s="%s"', $attr_name, $data ) if $data ne '';
		}
		
		if ( $self->isSelfClosing( $tag ) ) {
			$out .= sprintf( '<%s%s />', $tag, $attr );
			next;
		}
		
		unless( exists( $node->{$tag}{content} ) ) {
			$out .= sprintf( '<%s%s></%s>', $tag, $attr, $tag );
			next;
		}
		
		my $content	= '';
		if ( ref( $node->{$tag}{content} ) eq 'HASH' ) {
			$content = $self->flattenNode( $node );
		} else {
			$content = $node->{$tag}{content};
		}
		$out .= sprintf( '<%s%s>%s</%s>', $tag, $attr, $content );
	}
	
	return $out;
}

# Build HTML block from nested hash of tags and their attributes
sub buildHTML {
	my ( $self, $node )	= @_;
	my $out	= '';
	
	foreach my $tag ( keys %{$node} ) {
		# Skip unless tag exists in whitelist
		next unless exists $self->{whitelist}{$tag};
		
		my $attr	= '';
		if ( exists( $node->{$tag}{attributes} ) ) {
			my %allowed_attrs =
			map { 
				$_ => 1 
			} @{ $self->{whitelist}{$tag}{attributes} // [] };
			
			foreach my $attr_name ( keys %{$node->{$tag}{attributes}} ) {
				# Skip unless attribute exists for this tag
				next unless $allowed_attrs{$attr_name};
				
				my $data	= 
				$node->{$tag}{attributes}{$attr_name} // '';
				
				$data		= 
				$self->filterAttribute( $tag, $attr_name, $data );
				
				$attr		.= 
				sprintf( ' %s="%s"', $attr_name, $data );
			}
		}
		
		# Ignore content if this is meant to be self-closing
		if ( 
			$self->isSelfClosing( $tag )		|| 
			$self->{whitelist}{$tag}{self_closing}	// 0 
		) {
			$out .= sprintf( '<%s%s />', $tag, $attr );
			next;
		}
		
		# No content?
		unless( exists( $node->{$tag}{content} ) ) {
			$out .= sprintf( '<%s%s></%s>', $tag, $attr, $tag );
			next;
		}
		
		my $content	= '';
		if ( ref( $node->{$tag}{content} ) eq 'HASH' ) {
			# Nesting isn't allowed?
			if ( $self->{whitelist}{$tag}{no_nest} // 0 ) {
				my $temp = $self->flattenNode($node->{$tag}{content});
				$content = escapeCode( $temp );
				$out	.= 
				sprintf( '<%s%s>%s</%s>', $tag, $attr, $content, $tag );
				next;
			}
			
			# Move on to child nodes
			$content = $self->buildHTML( $node->{$tag}{content} );
		} else {
			$content = escapeCode( $node->{$tag}{content} );
		}
		
		$out .= sprintf( '<%s%s>%s</%s>', $tag, $attr, $content, $tag );
	}
	
	return $out;
}

# Remove HTML cruft
sub cleanHTML {
	my ( $self, $html ) = @_;
	
	# Document type
	$html =~ s/<!DOCTYPE[^>]*>//i;
	
	# Comments
	$html =~ s/<!--.*?-->//gs;
	
	# XML etc...
	$html =~ s{<!\[CDATA\[.*?\]\]>}{}gs;
	
	# Remove OpenOffice/LibreOffice-specific tags
	$html =~ s/<\/?(office|text|style|draw|table):[^>]*>//gi;

	# Remove proprietary MS Word content
	
	# Word tags
	$html =~ s/<\/?(o:p|v:shape|w:worddocument|xml)[^>]*>//gi;
	
	# inline styles
	$html =~ s/style="[^"]*mso-[^"]*"//gi;
	
	# Conditional comments like <!--[if mso]>
	$html =~ s/<!--\[if[^>]*\]>.*?<!\[endif\]-->//gsi;
	
	return $html;
}

# Protect content within code blocks
sub protectCode {
	my ( $self, $html, $blocks, $segments )	= @_;
	
	while ( $html=~ s{(.*?)<code\b([^>]*)>(.*?)</code>}{}gis ) {
		my $text	= $1;
		my $attr	= $2;
		my $data	= $3;
		
		trim( \$text );
		trim( \$attr );
		trim( \$data );
		push( @$segments, $text ) if ( $text ne '' );	# Skip empty
		push( @$segments, '__CODE_BLOCK__' );		# Placeholder
		
		# Code block
		push( @$blocks, { attributes => $attr, content => $data } );
	}
	
	push( @$segments, $html ) if $html ne '';
}

# Restore protected code blocks
sub restoreCode {
	my ( $self, $blocks, $segments )	= @_;

	my @out	= 
	map{
		if ( $_ eq '__CODE_BLOCK__' ) { 
			my $code	= shift( @$blocks );
			my $data	= $code->{content} // '';
			my $attr	= $code->{attributes} // '';
			
			$attr	= " $attr" if $attr ne '';
			"<code${attr}>${data}</code>";
		} else {
			$_ # As-is
		}			
	} @$segments;
	
	return join( '', @out );
}

# Escape and encode <code> blocks
sub escapeWithCode {
	my ( $self, $html )	= @_;
	
	# Protected content
	my @segments;
	my @blocks;
	
	$self->protectCode( $html, \@blocks, \@segments );
	return '' unless @segments;
	
	foreach my $segment ( @segments ) {
		unless ( $segment eq '__CODE_BLOCK__' ) {
			$segment = $self->cleanHTML( $segment );
		}
	}
	
	return $self->restoreCode( \@blocks, \@segments );
}

sub load {
	my ( $self, $data ) = @_;
	
	$data		= $self->escapeWithCode( $data );
	my %html	= $self->parseHTML( $data );
	my $out		= $self->buildHTML( \%html );
}


1;


# HTML Tag whitelist
__DATA__

{
	"p": {
		"attributes": [ "style", "class", "align", 
			"data-pullquote", "data-video", "data-media" ]
	},
	"div": {
		"attributes": [ "style", "class", "align" ]
	},
	"span": {
		"attributes": [ "style", "class" ]
	},
	"br": {
		"attributes": [ "style", "class" ],
		"self_closing": 1,
		"no_nest": 1
	},
	"hr": {
		"attributes": [ "style", "class" ],
		"self_closing": 1,
		"no_nest": 1
	},
	"h1": {
		"attributes": [ "style", "class" ]
	},
	"h2": {
		"attributes": [ "style", "class" ]
	},
	"h3": {
		"attributes": [ "style", "class" ]
	},
	"h4": {
		"attributes": [ "style", "class" ]
	},
	"h5": {
		"attributes": [ "style", "class" ]
	},
	"h6": {
		"attributes": [ "style", "class" ]
	},
	"strong": {
		"attributes": [ "style", "class" ]
	},
	"em": {
		"attributes": [ "style", "class" ]
	},
	"u": {
		"attributes": [ "style", "class" ]
	},
	"strike": {
		"attributes": [ "style", "class" ]
	},
	"del": {
		"attributes": [ "style", "class", "cite", "datetime" ],
		"uri_attr": [ "cite" ]
	},
	"ins": {
		"attributes": [ "style", "class", "cite", "datetime" ],
		"uri_attr": [ "cite" ]
	},
	"ol": {
		"attributes": [ "style", "class" ]
	},
	"ul": {
		"attributes": [ "style", "class" ]
	},
	"li": {
		"attributes": [ "style", "class" ]
	},
	"code": {
		"attributes": [ "style", "class" ],
		"no_nest": 1
	},
	"pre": {
		"attributes": [ "style", "class" ]
	},
	"sup": {
		"attributes": [ "style", "class" ]
	},
	"sub": {
		"attributes": [ "style", "class" ]
	},
	"a": {
		"attributes": [ "style", "class", "rel", "title", "href" ],
		"uri_attr": [ "href" ]
	},
	"img": {
		"attributes": [ "style", "class", "src", "height", "width", 
			"alt", "title", "srcset", "sizes", 
			"data-srcset", "data-src", "data-sizes" ],
		"uri_attr": [ "data-src", "data-srcset", "srcset", "src" ],
		"no_nest": 1
	},
	"figure": {
		"attributes": [ "style", "class" ]
	},
	"figcaption": {
		"attributes": [ "style", "class" ]
	},
	"picture": {
		"attributes": [ "style", "class" ]
	},
	"table": {
		"attributes": [ "style", "class", "cellspacing", 
			"border-collapse", "cellpadding" ]
	},
	"thead": {
		"attributes": [ "style", "class" ]
	},
	"tbody": {
		"attributes": [ "style", "class" ]
	},
	"tfoot": {
		"attributes": [ "style", "class" ]
	},
	"tr": {
		"attributes": [ "style", "class" ]
	},
	"td": {
		"attributes": [ "style", "class", "colspan", "rowspan" ]
	},
	"th": {
		"attributes": [ "style", "class", "scope", 
			"colspan", "rowspan" ]
	},
	"caption": {
		"attributes": [ "style", "class" ]
	},
	"col": {
		"attributes": [ "style", "class" ]
	},
	"colgroup": {
		"attributes": [ "style", "class" ]
	},
	"address": {
		"attributes": [ "style", "class" ]
	},
	"summary": {
		"attributes": [ "style", "class" ]
	},
	"details": {
		"attributes": [ "style", "class" ]
	},
	"q": {
		"attributes": [ "style", "class", "cite" ],
		"uri_attr": [ "cite" ],
		"no_nest": 1
	},
	"cite": {
		"attributes": [ "style", "class" ]
	},
	"abbr": {
		"attributes": [ "style", "class", "title" ]
	},
	"dfn": {
		"attributes": [ "style", "class", "title" ]
	},
	"blockquote": {
		"attributes": [ "style", "class", "cite" ],
		"uri_attr": [ "cite" ]
	}
}

