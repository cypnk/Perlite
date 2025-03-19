
# Markdown and basic HTML formatting
package Perlite::Format;

use strict;
use warnings;

use Exporter qw( import );

use Perlite::Filter qw( trim mergeArrayUnique );

our @EXPORT_OK	= 
qw( replace startProtectedTags endProtectedTags formatTable formatLists makeParagraphs );


# Template placeholder replacements
sub replace {
	my ( $tpl, $data, $clean ) = @_;
	
	while ( my ( $term, $html ) = each %$data ) {
		$tpl =~ s/\{$term\}/$html/ge;
	}
	
	$clean = $clean // 1;
	
	# Remove any unset placeholders
	if ( $clean == 1 ) {
		$tpl =~ s/\{.*\}//g;
	}
	
	return $tpl;
}

# Wrap sent HTML with protected placeholders, optionally adding new tags
sub startProtectedTags {
	my ( $html, $ns )	= @_;
	
	# Base level protected tags
	my @protected	= 
	( 'p', 'ul', 'ol', 'pre', 'code', 'table', 'figure', 'figcaption', 
		'address', 'details', 'span', 'embed', 'video', 'audio', 
		'textarea', 'input' );
	
	if ( $ns ) {
		@protected = @{ mergeArrayUnique( \@protected, $ns ) };
	}
	
	my $tags	= join( '|', @protected );
	
	# Wrap protected tags in placeholders
	$$html		=~ 
	s|(<($tags)[^>]*>.*?</\2>)|__PROTECT__$1__ENDPROTECT__|gs;
}

# Restore protected tags
sub endProtectedTags {
	my ( $html )		= @_;
	
	$$html		=~ s/__PROTECT__(.*?)__ENDPROTECT__/$1/g;
}

# Table data row
sub formatRow {
	my ( $row, $header )	= @_;
	$header		//= 0;
	
	my $tag		= $header ? 'th' : 'td';
	
	# Split on pipe symbol, skipping escaped pipes '\|'
	my @data	= split( /(?<!\\)\|/, $row );
	my $html	= join( '', map { "<$tag>$_</$tag>" } @data );
	
	return "<tr>$html</tr>\n";
}

# Convert ASCII table to HTML
sub formatTable {
	my ( $table ) = @_;
	my $html	= '';
	
	# Lines = Rows
	my @rows	= split( /\n/, $table );
	
	# In header row, if true
	my $first	= 1;
	
	foreach my $row ( @rows ) {
		# Trim
		trim( \$row );
		
		# Skip empty rows or lines with just separator
		next if $row eq '' || $row =~ /^(\+|-)+$/;
		
		# First round is the header
		$html	.= formatRow( $row, $first );
		next unless $first;
		
		$first	= 0;
	}
	
	return "<table>$html</table>\n";
}

# Close open list types
sub formatCloseList {
	my ( $lstack, $indent, $html, $ltype ) = @_;
	while (
		@$lstack				&&
		$lstack->[-1]{indent} > $indent		&&
		$lstack->[-1]{type} eq $ltype
	) {
		$$html .= "</$ltype>\n";
		pop @$lstack;
	}
}

# Create new list type
sub formatNewList {
	my ( $lstack, $html, $indent, $ltype ) = @_;
	if (
		!@$lstack				||
		$lstack->[-1]{type} ne $ltype		||
		$lstack->[-1]{indent} != $indent
	) {
		# Close the current list if needed
		if ( @$lstack && $lstack->[-1]{type} eq $ltype ) {
			$$html .= "</$ltype>\n"
		}
		
		# Start a new list
		$$html .= "<$ltype>\n";
		push( @$lstack, { type => $ltype, indent => $indent } ) ;
	}
}

# Finish closing any remaining open list types based on stack
sub formatEndLists {
	my ( $lstack, $html ) = @_;
	while ( @$lstack ) {
		$$html .= 
		( $lstack->[-1]{type} eq 'ul' ) ? '</ul>' : (
			( $lstack->[-1]{type} eq 'ol' ) ? '</ol>' : '</dl>'
		);
		pop @$lstack;
	}
}

# Convert indented lists into HTML lists
sub formatListBlock {
	my ( $text ) = @_;

	my @lines = split /\n/, $text;
	my $html = '';
	my @lstack;  # Stack to manage nested lists
	
	foreach my $line ( @lines ) {
		# Match ordered list items
		if ( $line =~ /^(\s*)([\*\+\d\.]+)\s+(.*)$/ ) {
			my $indent	= length( $1 );
			my $marker	= $2;
			my $content	= $3;
			
			# Unordered type
			if ( $marker =~ /^[\*\+]/ ) {
				# Close ordered list if needed
				formatCloseList( \@lstack, \$html, $indent, 'ol');
				
				# Start a new unordered list if needed
				formatNewList( \@lstack, \$html, $indent, 'ul');
			
			# Ordered type
			} else {
				# Close unordered list if needed
				formatCloseList( \@lstack, \$html, $indent, 'ul');
				
				# Start a new ordered list if needed
				formatNewList( \@lstack, \$html, $indent, 'ol');
			}
			$html .= "<li>$content</li>\n";
			next;
		}
		
		# Close any remaining open lists before adding non-list content
		formatEndLists( \@lstack, $html );
		$html .= "$line\n";
	}

	# Close any remaining open lists at the end
	formatEndLists( \@lstack, \$html );
	return $html;
}

# Convert plain text lists to HTML list blocks
sub formatLists {
	my ( $text )	= @_;
	my @lists;
	
	# Prevent formatting inside existing block level tags
	startProtectedTags( \$text );
	
	# Save a placeholder after finding each list block
	while ( $text =~ /(__PROTECT__(.*?)__ENDPROTECT__)|([^\r\n]+)/g ) {
		if ( !defined( $3 ) ) {
			next;
		}
		
		my $idx	= scalar( @lists );
		push( @lists, { index => $idx, html => $3 } );
		$text =~ s/$&/__STARTLIST__${idx}__ENDLIST__/;
	}
	
	for my $block ( @lists ) {
		# Format the non-protected text block
		$block->{html} = formatListBlock( $block->{html} );
		
		# Restore from placeholder
		$text =~ 
		s/__STARTLIST__$block->{index}__ENDLIST__/$block->{html}/g;
	}
	
	# Restore other block level tags
	endProtectedTags( \$text );
	return $text;
}

# Wrap body text and line breaks in paragraphs
sub makeParagraphs {
	my ( $html, $ns )	= @_;
	
	startProtectedTags( \$html, $ns );
	
	# Wrap paragraphs
	$html		=~ 
	s/(?<!__PROTECT__)\r?\n\s*\r?\n(?!__ENDPROTECT__)/<\/p><p>/g;
	
	$html		= 
	"<p>$html</p>" unless $html =~ /^<p>/ || $html =~ /__PROTECT__/;
	
	endProtectedTags( \$html );
	return $html;
}

1;

