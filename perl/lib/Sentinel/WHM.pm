package Sentinel::WHM;

# The WHM (root) page: active bans, a manual block form, recent failed
# logins, quarantined files on the server and the audit log.

use strict;
use warnings;

use Sentinel::Client ();
use Sentinel::HTML qw();

*esc      = \&Sentinel::HTML::esc;
*fmt_time = \&Sentinel::HTML::fmt_time;


sub _caller {
    return { role => 'admin', remote_ip => ( $ENV{REMOTE_ADDR} // '' ) };
}

# Runs a POSTed action. Returns (message, error).
sub handle_post {
    my ($form) = @_;
    my $action = $form->{action} // '';
    my %verbs = ( block => 'block_ip', unblock => 'unblock_ip' );
    my $verb = $verbs{$action} or return ( undef, 'Unknown action.' );

    my %args = ( ip => $form->{ip} // '' );
    if ( $action eq 'block' ) {
        $args{minutes} = $form->{minutes} // '';
        $args{reason}  = $form->{reason}  // '';
    }
    my $r = Sentinel::Client::call( verb => $verb, caller => _caller(), args => \%args );
    return ( undef, $r->{error} ) unless $r->{ok};
    return ( $action eq 'block' ? "Blocked $args{ip}." : "Unblocked $args{ip}.", undef );
}

# Fetches everything the page shows.
sub load {
    my %d;
    for my $part ( [ bans => 'list_bans', {} ], [ failures => 'recent_failures', { limit => 50 } ],
        [ quarantine => 'list_quarantine', {} ], [ audit => 'audit_log', { limit => 50 } ] )
    {
        my ( $key, $verb, $args ) = @$part;
        my $r = Sentinel::Client::call( verb => $verb, caller => _caller(), args => $args );
        if ( !$r->{ok} ) {
            $d{error} //= $r->{error};
            $d{$key} = [];
            next;
        }
        $d{$key} = $r->{data} || [];
    }
    return \%d;
}

sub body {
    my (%a) = @_;
    my $d = $a{data} || {};
    my @o;

    push @o, '<div class="sentinel">';
    push @o, Sentinel::HTML::alert( 'ok',    $a{message} );
    push @o, Sentinel::HTML::alert( 'error', $a{error} // $d->{error} );

    # Active bans
    my $bans = $d->{bans} || [];
    push @o, '<h2>Blocked IP addresses</h2>';
    if (@$bans) {
        push @o, '<table class="table table-striped"><thead><tr><th>IP</th><th>Reason</th>'
          . '<th>Blocked</th><th>Expires</th><th></th></tr></thead><tbody>';
        for my $b (@$bans) {
            push @o, '<tr><td>' . esc( $b->{ip} ) . '</td><td>' . esc( $b->{reason} )
              . ( $b->{manual} ? ' <span class="label label-info">manual</span>' : '' ) . '</td>'
              . '<td>' . fmt_time( $b->{since} ) . '</td><td>' . fmt_time( $b->{expires} ) . '</td>'
              . '<td><form method="post" action="index.cgi">'
              . '<input type="hidden" name="action" value="unblock">'
              . '<input type="hidden" name="ip" value="' . esc( $b->{ip} ) . '">'
              . '<button type="submit" class="btn btn-default btn-sm">Unblock</button></form></td></tr>';
        }
        push @o, '</tbody></table>';
    }
    else {
        push @o, '<p>No IP addresses are blocked right now.</p>';
    }

    push @o, '<form method="post" action="index.cgi" class="form-inline">'
      . '<input type="hidden" name="action" value="block">'
      . '<label>Block IP <input type="text" name="ip" class="form-control" required maxlength="45"></label> '
      . '<label>for <input type="number" name="minutes" class="form-control" min="1" value="60"> minutes</label> '
      . '<label>Reason <input type="text" name="reason" class="form-control" maxlength="200"></label> '
      . '<button type="submit" class="btn btn-primary">Block</button></form>';

    # Recent failures
    my $f = $d->{failures} || [];
    push @o, '<h2>Recent failed logins</h2>';
    if (@$f) {
        push @o, '<table class="table table-striped"><thead><tr><th>Time</th><th>IP</th>'
          . '<th>User</th><th>Service</th></tr></thead><tbody>';
        push @o, '<tr><td>' . fmt_time( $_->{time} ) . '</td><td>' . esc( $_->{ip} )
          . ( $_->{banned} ? ' <span class="label label-danger">blocked</span>' : '' )
          . '</td><td>' . esc( $_->{user} ) . '</td><td>' . esc( $_->{service} ) . '</td></tr>'
          for @$f;
        push @o, '</tbody></table>';
    }
    else {
        push @o, '<p>No failed logins since the service started.</p>';
    }

    # Quarantine
    my $q = $d->{quarantine} || [];
    push @o, '<h2>Quarantined files</h2>';
    if (@$q) {
        push @o, '<table class="table table-striped"><thead><tr><th>Account</th><th>File</th>'
          . '<th>Reason</th><th>When</th></tr></thead><tbody>';
        push @o, '<tr><td>' . esc( $_->{user} ) . '</td><td>' . esc( $_->{path} ) . '</td><td>'
          . esc( $_->{reason} ) . '</td><td>' . fmt_time( $_->{quarantined} ) . '</td></tr>'
          for @$q;
        push @o, '</tbody></table>';
    }
    else {
        push @o, '<p>No files are in quarantine.</p>';
    }

    # Audit log
    my $al = $d->{audit} || [];
    push @o, '<h2>Audit log</h2>';
    if (@$al) {
        push @o, '<table class="table table-condensed"><thead><tr><th>Time</th><th>Who</th>'
          . '<th>From</th><th>Action</th><th>Details</th><th>Result</th></tr></thead><tbody>';
        for my $e (@$al) {
            my $args = $e->{args} || {};
            my $details = join ', ', map { "$_=$args->{$_}" } sort keys %$args;
            push @o, '<tr><td>' . fmt_time( $e->{time} ) . '</td><td>' . esc( $e->{actor} ) . '</td><td>'
              . esc( $e->{remote_ip} ) . '</td><td>' . esc( $e->{verb} ) . '</td><td>' . esc($details)
              . '</td><td>' . ( $e->{ok} ? 'OK' : 'Failed: ' . esc( $e->{error} ) ) . '</td></tr>';
        }
        push @o, '</tbody></table>';
    }
    else {
        push @o, '<p>No actions recorded yet.</p>';
    }

    push @o, '</div>';
    return join "\n", grep { length } @o;
}

1;
