use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Test::More;
use Sentinel::HTML ();
use Sentinel::WHM ();
use Sentinel::CPanel ();

subtest 'esc and parse_query' => sub {
    is( Sentinel::HTML::esc(q{<a href="x">'&}), '&lt;a href=&quot;x&quot;&gt;&#39;&amp;' );
    is_deeply( Sentinel::HTML::parse_query('a=1&b=x+y%3Cz&c'), { a => '1', b => 'x y<z', c => '' } );
    is( Sentinel::HTML::fmt_time('2026-11-25T10:00:01Z'), '2026-11-25 10:00:01 UTC' );
};

my $xss = '<script>alert(1)</script>';

subtest 'WHM page escapes daemon data' => sub {
    my $html = Sentinel::WHM::body(
        data => {
            bans       => [ { ip => '203.0.113.9', reason => $xss, since => '2026-11-25T10:00:00Z', expires => '2026-11-25T11:00:00Z' } ],
            failures   => [ { ip => '203.0.113.9', user => $xss, service => 'cpaneld', time => '2026-11-25T10:00:00Z', banned => 1 } ],
            quarantine => [ { user => 'alice', path => "public_html/$xss.php", reason => 'x', quarantined => '2026-11-25T10:00:00Z' } ],
            audit      => [ { actor => 'user:alice', verb => 'quarantine', args => { path => $xss }, ok => 1, time => '2026-11-25T10:00:00Z' } ],
        },
        error => $xss,
    );
    unlike( $html, qr/<script>/, 'no raw script tag' );
    like( $html, qr/203\.0\.113\.9/, 'ban shown' );
    like( $html, qr/name="action" value="unblock"/, 'unblock form' );
    like( $html, qr/method="post"/, 'state changes use POST' );
    unlike( $html, qr/method="get"/i, 'no GET forms' );
};

subtest 'WHM empty states' => sub {
    my $html = Sentinel::WHM::body( data => {} );
    like( $html, qr/No IP addresses are blocked/ );
    like( $html, qr/No failed logins/ );
};

subtest 'cPanel page' => sub {
    my $html = Sentinel::CPanel::body(
        data => {
            quarantined => [ { id => 'a' x 32, path => "public_html/$xss", reason => 'r', quarantined => '2026-11-25T10:00:00Z' } ],
            allowlisted => [$xss],
        }
    );
    unlike( $html, qr/<script>/, 'no raw script tag' );
    like( $html, qr/value="a{32}"/, 'restore form carries id' );
};

subtest 'cPanel actions map only to the four AdminBin functions' => sub {
    my @calls;
    my $fake = sub { push @calls, [@_]; return { ok => 1 } };

    my ( $msg, $err ) = Sentinel::CPanel::handle_post( $fake, { action => 'quarantine', path => 'public_html/x.php', user => 'bob' } );
    is( $msg, 'File moved to quarantine.' );
    is_deeply( $calls[-1], [ 'QUARANTINE', 'public_html/x.php' ], 'user field is not forwarded' );

    Sentinel::CPanel::handle_post( $fake, { action => 'restore', id => 'f' x 32 } );
    is_deeply( $calls[-1], [ 'RESTORE', 'f' x 32 ] );

    Sentinel::CPanel::handle_post( $fake, { action => 'allowlist', path => 'p' } );
    is_deeply( $calls[-1], [ 'ALLOWLIST_FILE', 'p' ] );

    my $n = @calls;
    ( $msg, $err ) = Sentinel::CPanel::handle_post( $fake, { action => 'block_ip', ip => '1.2.3.4' } );
    is( $err, 'Unknown action.' );
    is( scalar @calls, $n, 'unknown action never reaches AdminBin' );

    ( $msg, $err ) = Sentinel::CPanel::handle_post( sub { { ok => 0, error => 'path is outside the account\'s home directory' } }, { action => 'quarantine', path => '../x' } );
    like( $err, qr/outside/ );
};

done_testing;
