package Sentinel::HTML;

# Small helpers shared by the WHM and cPanel pages. Everything shown on a
# page that came from a log, a file name or the daemon goes through esc().

use strict;
use warnings;

use POSIX qw(strftime);

sub esc {
    my ($s) = @_;
    $s = '' unless defined $s;
    $s =~ s/&/&amp;/g;
    $s =~ s/</&lt;/g;
    $s =~ s/>/&gt;/g;
    $s =~ s/"/&quot;/g;
    $s =~ s/'/&#39;/g;
    return $s;
}

# Daemon times are RFC 3339 strings; show them compactly.
sub fmt_time {
    my ($t) = @_;
    return '-' unless defined $t && length $t;
    if ( $t =~ /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/ ) {
        return "$1 $2 UTC";
    }
    return esc($t);
}

# Parses an application/x-www-form-urlencoded string.
sub parse_query {
    my ($q) = @_;
    my %out;
    for my $pair ( split /[&;]/, $q // '' ) {
        my ( $k, $v ) = split /=/, $pair, 2;
        next unless defined $k && length $k;
        for ( $k, $v ) {
            next unless defined;
            tr/+/ /;
            s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge;
        }
        $out{$k} = $v // '';
    }
    return \%out;
}

# Reads a POST body from STDIN (capped at 64 KB).
sub read_post {
    return {} unless ( $ENV{REQUEST_METHOD} // '' ) eq 'POST';
    my $len = $ENV{CONTENT_LENGTH} // 0;
    return {} unless $len =~ /^\d+$/ && $len > 0 && $len <= 65536;
    my $body = '';
    read( STDIN, $body, $len );
    return parse_query($body);
}

sub alert {
    my ( $kind, $msg ) = @_;
    return '' unless defined $msg && length $msg;
    my $class = $kind eq 'error' ? 'alert-danger' : 'alert-success';
    return qq{<div class="alert $class" role="alert">} . esc($msg) . '</div>';
}

1;
