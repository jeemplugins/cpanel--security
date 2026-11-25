# End-to-end: start the real daemon (dry-run firewall), feed it a brute-force
# attack through the login log, and drive it through Sentinel::Client the
# way the WHM page does.
#
# Needs root (the daemon only accepts uid 0 peers) and a built binary:
#   make build && sudo SENTINELD=dist/sentineld prove -Iperl/lib perl/t/integration.t

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Test::More;
use File::Temp qw(tempdir);
use JSON::PP ();
use Time::HiRes qw(sleep);
use POSIX qw(strftime);
use Sentinel::Client ();

my $bin = $ENV{SENTINELD};
plan skip_all => 'set SENTINELD to a built sentineld binary' unless $bin && -x $bin;
plan skip_all => 'must run as root' unless $> == 0;

my $dir    = tempdir( CLEANUP => 1 );
my $sock   = "$dir/s.sock";
my $log    = "$dir/login_log";
my $config = "$dir/config.json";

open my $lf, '>', $log or die;
close $lf;

open my $cf, '>', $config or die;
print {$cf} JSON::PP->new->encode(
    {
        socket      => $sock,
        state_dir   => "$dir/state",
        audit_log   => "$dir/audit.log",
        login_log   => $log,
        brute_force => { enabled => JSON::PP::true, threshold => 3, window_minutes => 10, ban_minutes => 60, allowlist => ['127.0.0.1'] },
    }
);
close $cf;

my $pid = fork // die;
if ( !$pid ) {
    open STDOUT, '>', "$dir/daemon.out";
    open STDERR, '>&', \*STDOUT;
    exec $bin, '-config', $config, '-dry-run' or die;
}
END { if ($pid) { kill "TERM", $pid; waitpid $pid, 0 } }

for ( 1 .. 50 ) { last if -S $sock; sleep 0.1 }
ok( -S $sock, 'daemon listening' ) or BAIL_OUT('daemon did not start');
is( ( stat $sock )[2] & 07777, 0600, 'socket is mode 0600' );

local $Sentinel::Client::SOCKET = $sock;
my $admin = { role => 'admin', remote_ip => '192.0.2.10' };
my $call  = sub { Sentinel::Client::call( verb => $_[0], caller => $admin, args => $_[1] || {} ) };

ok( $call->('status')->{ok}, 'status' );

# Simulate a brute-force attack: 3 failures from one IP, 2 from the allowlist.
my $ts = strftime( '%m/%d/%Y:%H:%M:%S -0000', gmtime );
open $lf, '>>', $log or die;
for my $ip ( ('203.0.113.66') x 3, ('127.0.0.1') x 3 ) {
    print {$lf} qq{$ip - root [$ts] "POST /login/?login_only=1 HTTP/1.1" FAILED LOGIN whostmgrd: user password incorrect\n};
}
close $lf;

my $bans;
for ( 1 .. 50 ) {
    $bans = $call->('list_bans')->{data} || [];
    last if @$bans;
    sleep 0.1;
}
is( scalar @$bans, 1, 'one IP blocked' );
is( $bans->[0]{ip}, '203.0.113.66', 'the attacker, not the allowlisted IP' );

my $fails = $call->( 'recent_failures', { limit => 10 } )->{data};
is( scalar @$fails, 6, 'six failures recorded' );

ok( $call->( 'unblock_ip', { ip => '203.0.113.66' } )->{ok}, 'unblock' );
is( scalar @{ $call->('list_bans')->{data} || [] }, 0, 'ban lifted' );

ok( !$call->( 'block_ip', { ip => '127.0.0.1' } )->{ok}, 'cannot block an allowlisted IP' );

# A user caller can't use admin verbs, and unknown accounts are refused.
my $r = Sentinel::Client::call( verb => 'list_bans', caller => { role => 'user', user => 'alice' } );
ok( !$r->{ok}, 'user cannot list bans' );

my $audit = $call->( 'audit_log', { limit => 20 } )->{data};
ok( ( grep { $_->{verb} eq 'auto_block' } @$audit ), 'auto block audited' );
ok( ( grep { $_->{verb} eq 'unblock_ip' && $_->{remote_ip} eq '192.0.2.10' } @$audit ), 'admin unblock audited with IP' );

kill "TERM", $pid;
waitpid $pid, 0;
undef $pid;

done_testing;
