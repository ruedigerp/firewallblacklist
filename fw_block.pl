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

my @networks = ('asian', 'russian');

sub newchain
{
  my $chainname = $_[0];
  ($rv, $out_ar, $errs_ar) = $ipt_obj->chain_exists('filter', $chainname);
  if ($rv) {
      print "$chainname chain exists.\n";
  }
  else
  {
    # print "$chainname chain does not exists. ";
    $ipt_obj->create_chain('filter', $chainname);
    # print "Create chain $chainname ";
    setchainrules($chainname);
  }
}
sub setchainrules
{
	my $chainname = $_[0];
	open(FH, $chainname . ".txt");
	my @host_cfg = <FH>;
	close FH;

	foreach my $cfg_line (@host_cfg)
	{
  	chomp $cfg_line;
  	if ( not $cfg_line =~ m/(^\#|^$)/  )
		{
			($rv, $out_ar, $errs_ar) = $ipt_obj->add_ip_rule($cfg_line, '0.0.0.0/0', 5, 'filter', $chainname, 'REJECT', { 'protocol' => 'tcp', 'd_port' => '22', 'comment' => "test: $host" });
		}
	}
}

sub flush_all_rules
{
	my $chainname = $_[0];
	# print "Delete Input Chain for $chainname\n";
	($rv, $out_ar, $errs_ar) = $ipt_obj->delete_ip_rule('0.0.0.0/0', '0.0.0.0/0', 'filter', 'INPUT', $chainname, { 'protocol' => 'tcp', 'd_port' => '22' });
	# print "Flush and delete $chainname\n";
  ($rv, $out_ar, $errs_ar) = $ipt_obj->run_ipt_cmd("/sbin/iptables -F $chainname; /sbin/iptables -X $chainname;");
}


foreach $net (@networks)
{
	print "Net: $net, set INPUT rule\n";
	flush_all_rules($net);
	newchain($net);
	($rv, $out_ar, $errs_ar) = $ipt_obj->add_ip_rule('0.0.0.0/0', '0.0.0.0/0', 5, 'filter', 'INPUT', $net, { 'protocol' => 'tcp', 'd_port' => '22' });
}

