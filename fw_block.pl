#!/usr/bin/perl

use IPTables::ChainMgr;

my %opts = (
  'iptables' => '/sbin/iptables',
  'iptout'   => '/tmp/iptables.out',
  'ipterr'   => '/tmp/iptables.err',
  'debug'    => 0,
  'verbose'  => 0,
  ### advanced options
  'ipt_alarm' => 0,  ### max seconds to wait for iptables execution.
  'ipt_exec_style' => 'waitpid',  ### can be 'waitpid', 'system', or 'popen'.
  'ipt_exec_sleep' => 0, ### add in time delay between execution of iptables commands (default is 0).
);

my $ipt_obj = new IPTables::ChainMgr(%opts) or die "[*] Could not acquire IPTables::ChainMgr object";
my $rv = 0;
my $out_ar = [];
my $errs_ar = [];

my @networks = ('asian');

sub newchain
{
  my $chainname = $_[0];
  ($rv, $out_ar, $errs_ar) = $ipt_obj->chain_exists('filter', $chainname);
  if ($rv) {
      print "$chainname chain exists.\n";
  }
  else
  {
    print "$chainname chain does not exists. ";
    $ipt_obj->create_chain('filter', $chainname);
    print "Create chain $chainname ";
    setchainrules($chainname);
  }
}
sub setchainrules 
{
	my $networks = $_[0];
	open(FH, $networks . ".txt");
	my @host_cfg = <FH>;
	close FH;

	foreach my $cfg_line (@host_cfg)
	{
  	chomp $cfg_line;
  	if ( not $cfg_line =~ m/(^\#|^$)/  )
		{
			# print "Test: $cfg_line\n";
			($rv, $out_ar, $errs_ar) = $ipt_obj->add_ip_rule($cfg_line, '0.0.0.0/0', 5, 'filter', $chainname, 'REJECT', { 'protocol' => 'tcp', 'd_port' => '22', 'comment' => "test: $host" });
		}
	}
}

foreach $net (@networks)
{
	newchain($net);
}

