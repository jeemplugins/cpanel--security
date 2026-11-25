package Sentinel::CPanel;

# The cPanel (account owner) page. It runs as the account's own user and
# reaches the daemon only through the Sentinel UAPI module, which calls the
# Sentinel AdminBin (root), which calls sentineld.

use strict;
use warnings;

use Sentinel::HTML ();

*esc      = \&Sentinel::HTML::esc;
*fmt_time = \&Sentinel::HTML::fmt_time;

# Map form actions to UAPI functions. Nothing else is callable.
my %ACTIONS = (
    quarantine => [ 'quarantine',     'path', 'File moved to quarantine.' ],
    restore    => [ 'restore',        'id',   'File restored.' ],
    allowlist  => [ 'allowlist_file', 'path', 'File marked as safe.' ],
);

# $uapi is a code ref: ($function, %args) -> { ok, data | error }.
# Production passes a wrapper around Cpanel::LiveAPI->uapi('Sentinel', ...).
sub handle_post {
    my ( $uapi, $form ) = @_;
    my $a = $ACTIONS{ $form->{action} // '' } or return ( undef, 'Unknown action.' );
    my ( $fn, $field, $done ) = @$a;
    my $r = $uapi->( $fn, $field => $form->{$field} // '' );
    return $r->{ok} ? ( $done, undef ) : ( undef, $r->{error} // 'Request failed.' );
}

sub body {
    my (%a) = @_;
    my $d = $a{data} || {};
    my @o;

    push @o, '<div class="sentinel">';
    push @o, Sentinel::HTML::alert( 'ok',    $a{message} );
    push @o, Sentinel::HTML::alert( 'error', $a{error} );

    push @o, '<h2>Quarantined files</h2>';
    my $q = $d->{quarantined} || [];
    if (@$q) {
        push @o, '<table class="table table-striped"><thead><tr><th>File</th><th>Reason</th>'
          . '<th>When</th><th></th></tr></thead><tbody>';
        for my $it (@$q) {
            push @o, '<tr><td>' . esc( $it->{path} ) . '</td><td>' . esc( $it->{reason} ) . '</td><td>'
              . fmt_time( $it->{quarantined} ) . '</td><td>'
              . '<form method="post" action="index.live.pl">'
              . '<input type="hidden" name="action" value="restore">'
              . '<input type="hidden" name="id" value="' . esc( $it->{id} ) . '">'
              . '<button type="submit" class="btn btn-default btn-sm">Restore</button></form></td></tr>';
        }
        push @o, '</tbody></table>';
    }
    else {
        push @o, '<p>No files from your account are in quarantine.</p>';
    }

    push @o, '<h2>Quarantine a file</h2>'
      . '<p>Moves a file out of your website into safe storage. You can restore it at any time.</p>'
      . '<form method="post" action="index.live.pl" class="form-inline">'
      . '<input type="hidden" name="action" value="quarantine">'
      . '<label>Path in your home folder <input type="text" name="path" class="form-control" '
      . 'placeholder="public_html/suspicious.php" required maxlength="4096"></label> '
      . '<button type="submit" class="btn btn-primary">Quarantine</button></form>';

    push @o, '<h2>Files marked as safe</h2>';
    my $al = $d->{allowlisted} || [];
    if (@$al) {
        push @o, '<ul>' . join( '', map { '<li>' . esc($_) . '</li>' } @$al ) . '</ul>';
    }
    else {
        push @o, '<p>None yet.</p>';
    }
    push @o, '<form method="post" action="index.live.pl" class="form-inline">'
      . '<input type="hidden" name="action" value="allowlist">'
      . '<label>Mark as safe <input type="text" name="path" class="form-control" required maxlength="4096"></label> '
      . '<button type="submit" class="btn btn-default">Save</button></form>';

    push @o, '</div>';
    return join "\n", grep { length } @o;
}

# Turns a Cpanel::LiveAPI uapi() return value into { ok, data | error }.
sub uapi_result {
    my ($r) = @_;
    my $res = ref $r eq 'HASH' ? ( $r->{cpanelresult}{result} // $r->{result} // $r ) : undef;
    return { ok => 0, error => 'The security service is unavailable.' } unless ref $res eq 'HASH';
    return { ok => 1, data => $res->{data} } if $res->{status};
    my $errs = ref $res->{errors} eq 'ARRAY' ? join( ' ', @{ $res->{errors} } ) : '';
    return { ok => 0, error => length $errs ? $errs : 'Request failed.' };
}

1;
