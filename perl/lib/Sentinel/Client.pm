package Sentinel::Client;

# Talks to sentineld over its Unix socket. Used by the WHM page and the
# AdminBin adapter, both of which run as root.

use strict;
use warnings;

use IO::Socket::UNIX ();
use JSON::PP ();

our $SOCKET  = '/run/sentinel/sentinel.sock';
our $TIMEOUT = 30;

my $JSON = JSON::PP->new->utf8->canonical;

# call(verb => 'list_bans', caller => {role => 'admin'}, args => {...})
# Returns the decoded response: { ok => 1, data => ... } or { ok => 0, error => '...' }.
sub call {
    my (%a) = @_;
    my %args = %{ $a{args} || {} };

    # The protocol takes string arguments only.
    for my $k ( keys %args ) {
        my $v = $args{$k};
        return { ok => 0, error => "argument $k must be a string" } if ref $v;
        $args{$k} = defined $v ? "$v" : '';
    }

    my $req = $JSON->encode( { verb => $a{verb}, caller => $a{caller}, args => \%args } );

    my $sock = IO::Socket::UNIX->new( Peer => $a{socket} // $SOCKET, Timeout => $TIMEOUT )
      or return { ok => 0, error => 'The Sentinel service is not running.' };

    local $SIG{ALRM} = sub { die "timeout\n" };
    my $line = eval {
        alarm $TIMEOUT;
        print {$sock} $req, "\n";
        $sock->shutdown(1);
        my $l = <$sock>;
        alarm 0;
        $l;
    };
    alarm 0;
    close $sock;

    return { ok => 0, error => 'The Sentinel service did not answer.' } unless defined $line && length $line;
    my $resp = eval { $JSON->decode($line) };
    return { ok => 0, error => 'The Sentinel service sent an invalid answer.' } unless ref $resp eq 'HASH';
    return $resp;
}

1;
