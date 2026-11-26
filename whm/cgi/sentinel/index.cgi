#!/usr/local/cpanel/3rdparty/bin/perl
#WHMADDON:sentinel:Sentinel Security
#ACLS:all

# WHM page for Sentinel. Installed to
# /usr/local/cpanel/whostmgr/docroot/cgi/sentinel/index.cgi
#
# CSRF: WHM only serves this script under a valid /cpsessXXXX/ session
# token in the URL, and every state change must be a POST.

use strict;
use warnings;

use lib '/usr/local/cpanel', '/usr/local/cpanel/3rdparty/sentinel/lib';

use Whostmgr::ACLS ();
use Sentinel::HTML ();
use Sentinel::WHM ();

Whostmgr::ACLS::init_acls();

my $headers = "X-Frame-Options: SAMEORIGIN\r\nX-Content-Type-Options: nosniff\r\n";

# Root only: the page can block IPs and shows every account's data.
if ( !Whostmgr::ACLS::hasroot() ) {
    print "Status: 403 Forbidden\r\nContent-Type: text/plain\r\n$headers\r\nAccess denied. This page requires root access.\n";
    exit 0;
}

my ( $message, $error );
if ( ( $ENV{REQUEST_METHOD} // '' ) eq 'POST' ) {
    ( $message, $error ) = Sentinel::WHM::handle_post( Sentinel::HTML::read_post() );
}

print "Content-Type: text/html; charset=utf-8\r\n$headers\r\n";

my $title       = 'Sentinel Security';
my $have_chrome = eval {
    require Whostmgr::HTMLInterface;
    Whostmgr::HTMLInterface::defheader( $title, '', '/cgi/sentinel/index.cgi' );
    1;
};
print "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>$title</title></head><body>\n" unless $have_chrome;

print Sentinel::WHM::body( data => Sentinel::WHM::load(), message => $message, error => $error ), "\n";

if ( !$have_chrome || !eval { Whostmgr::HTMLInterface::deffooter(); 1 } ) {
    print "</body></html>\n";
}
