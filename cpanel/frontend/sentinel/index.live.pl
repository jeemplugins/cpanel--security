#!/usr/local/cpanel/3rdparty/bin/perl

# cPanel page for Sentinel (Jupiter theme). Runs as the account's own
# user. Installed to /usr/local/cpanel/base/frontend/jupiter/sentinel/.
#
# It reaches the daemon through UAPI (Cpanel::API::Sentinel), because
# cPanel 138 refuses AdminBin calls made directly from uncompiled Perl.
#
# CSRF: cPanel only serves this page under a valid /cpsessXXXX/ token, and
# every state change must be a POST.

use strict;
use warnings;

use lib '/usr/local/cpanel', '/usr/local/cpanel/3rdparty/sentinel/lib';

use Cpanel::LiveAPI ();
use Sentinel::HTML ();
use Sentinel::CPanel ();

my $cpanel = Cpanel::LiveAPI->new();

my $uapi = sub {
    my ( $fn, %args ) = @_;
    my $r = eval { $cpanel->uapi( 'Sentinel', $fn, \%args ) };
    return Sentinel::CPanel::uapi_result($r);
};

my ( $message, $error );
if ( ( $ENV{REQUEST_METHOD} // '' ) eq 'POST' ) {
    ( $message, $error ) = Sentinel::CPanel::handle_post( $uapi, Sentinel::HTML::read_post() );
}

my $findings = $uapi->('list_findings');
$error //= $findings->{error} unless $findings->{ok};

print "Content-Type: text/html; charset=utf-8\r\n\r\n";
print $cpanel->header('Security');
print Sentinel::CPanel::body( data => ( $findings->{ok} ? $findings->{data} : {} ), message => $message, error => $error ), "\n";
print $cpanel->footer();
$cpanel->end();
