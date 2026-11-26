package Cpanel::API::Sentinel;

# UAPI module for the cPanel page. Runs inside cPanel's own (compiled)
# API process as the account user, and forwards to the Sentinel AdminBin
# module, which runs as root and talks to sentineld.
#
# Installed to /usr/local/cpanel/Cpanel/API/Sentinel.pm.
#
#   uapi --user=alice Sentinel list_findings
#   uapi --user=alice Sentinel quarantine path=public_html/x.php
#   uapi --user=alice Sentinel restore id=<32 hex>
#   uapi --user=alice Sentinel allowlist_file path=public_html/ok.php

use strict;
use warnings;

use Cpanel::AdminBin::Call ();

our $VERSION = '0.1';

sub list_findings {
    my ( $args, $result ) = @_;
    return _call( $result, 'LIST_FINDINGS' );
}

sub quarantine {
    my ( $args, $result ) = @_;
    return _call( $result, 'QUARANTINE', scalar $args->get('path') );
}

sub restore {
    my ( $args, $result ) = @_;
    return _call( $result, 'RESTORE', scalar $args->get('id') );
}

sub allowlist_file {
    my ( $args, $result ) = @_;
    return _call( $result, 'ALLOWLIST_FILE', scalar $args->get('path') );
}

sub _call {
    my ( $result, $fn, @args ) = @_;
    my $r = eval { Cpanel::AdminBin::Call::call( 'Sentinel', 'Sentinel', $fn, @args ) };
    if ( ref $r ne 'HASH' ) {
        $result->error('The security service is unavailable.');
        return 0;
    }
    if ( !$r->{ok} ) {
        # [_1] keeps maketext from interpreting brackets in the message.
        $result->error( '[_1]', $r->{error} // 'Request failed.' );
        return 0;
    }
    $result->data( $r->{data} );
    return 1;
}

1;
