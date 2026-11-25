#!/usr/local/cpanel/3rdparty/bin/perl

# cPanel page for Sentinel (Jupiter theme). Runs as the account's own
# user. Installed to /usr/local/cpanel/base/frontend/jupiter/sentinel/.
#
# CSRF: cPanel only serves this page under a valid /cpsessXXXX/ token, and
# every state change must be a POST.

use strict;
use warnings;

use lib '/usr/local/cpanel', '/usr/local/cpanel/3rdparty/sentinel/lib';

use Cpanel::LiveAPI ();
use Cpanel::AdminBin::Call ();
use Sentinel::HTML ();
use Sentinel::CPanel ();

my $cpanel = Cpanel::LiveAPI->new();

my $adminbin = sub {
    my ( $fn, @args ) = @_;
    my $r = eval { Cpanel::AdminBin::Call::call( 'Sentinel', 'Sentinel', $fn, @args ) };
    return { ok => 0, error => 'The security service is unavailable.' } unless ref $r eq 'HASH';
    return $r;
};

my ( $message, $error );
if ( ( $ENV{REQUEST_METHOD} // '' ) eq 'POST' ) {
    ( $message, $error ) = Sentinel::CPanel::handle_post( $adminbin, Sentinel::HTML::read_post() );
}

my $findings = $adminbin->('LIST_FINDINGS');
$error //= $findings->{error} unless $findings->{ok};

print "Content-Type: text/html; charset=utf-8\r\n\r\n";
print $cpanel->header('Security');
print Sentinel::CPanel::body( data => ( $findings->{ok} ? $findings->{data} : {} ), message => $message, error => $error ), "\n";
print $cpanel->footer();
$cpanel->end();
