#!/usr/bin/perl

#Libraries to use
#use strict;
use lib "/usr/lib/nagios/plugins";

use Getopt::Std;
use Data::Dumper;
use XML::Simple;


use vars qw($opt_h $opt_H $opt_C $opt_M $opt_U $opt_P);
my $currentStatus;
my $justStatus;
my $exitcode=3;
my @statusList;
my $val;
my $criticals=0;

if ($#ARGV le 0) {
	print "You really should have specfied a switch. Displaying the help.\n";
	$opt_h = true;
} else {
        getopts('hH:C:M:U:P:');
}

## Display Help
if ($opt_h){
        print "::Juniper SRX Check Instructions::\n\n";
        print " -h,             Display this help information\n";
        print " -H,             Hostname or IP to check\n";
        print " -U,             Username to use\n";
        print " -P,             User Password\n"; 
        print " -M,             Specify a message to return on failure\n";
        print " \n";
        exit 0;
}

if (!$opt_H){
	print "You must specify a Hostname or IP to check (-H)\n";
	exit 3;
}

if (!$opt_U){
        print "You must specify a Username to use (-U)\n";
        exit 3;
}

if (!$opt_P){
        print "You must specify a password for the user (-P)\n";
        exit 3;
}


if($opt_C =~ /re_ctrlpn_memusage/){
    $xml = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show chassis routing-engine '|' display xml"`;
        $parser = XMLin($xml) ;
        $memusage = $parser->{'route-engine-information'}->{'route-engine'}->{'memory-control-plane-util'};
        if (not (defined $memusage)){
               print"Critical:Not able to retrieve control plane memory usage";
               exit 2;
        }
        my $perfdata .= "|"
         ."ctrl_plane_mem_usage=$memusage%";
        if ($memusage >95){
                print"Critical:The control plane memory usage is $memusage% $perfdata";
                exit 2;
        }else{
                print"OK:The control plane memory usage is $memusage% $perfdata";
                exit 0;
        }

}elsif($opt_C =~ /re_system_cpu/){
    $xml = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show chassis routing-engine '|' display xml"`;
    $parser = XMLin($xml) ;
    $kernelcpu = $parser->{'route-engine-information'}->{'route-engine'}->{'cpu-system'};
    my $perfdata .= "|"
         ."kernelcpu=$kernelcpu%";
    if (not (defined $kernelcpu)){
               print"Critical:Not able to retrieve Routing engine system cpu usage";
               exit 2;
    }
    if ($kernelcpu > 95){
                print"Critical:Routing engine system cpu usage is $kernelcpu% $perfdata";
                exit 2;
        }else{
                print"OK:Routing engine system cpu usage is $kernelcpu% $perfdata";
                exit 0;
        }

}elsif($opt_C =~ /re_load_avg_one/){
    $xml = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show chassis routing-engine '|' display xml"`;
    $parser = XMLin($xml) ;
    $loadavg = $parser->{'route-engine-information'}->{'route-engine'}->{'load-average-one'};
    my $perfdata .= "|"
         ."loadavg=$loadavg%";
    if (not (defined $loadavg)){
               print"Critical:Not able to retrieve Routing engine load_average_one";
               exit 2;
    }
    if ($loadavg > 1){
                print"Critical:Routing engine load_average_one is $loadavg% $perfdata";
                exit 2;
        }else{
                print"OK:Routing engine load_average_one is $loadavg% $perfdata";
                exit 0;
        }
}elsif($opt_C =~ /idlecpu/){
    $currentStatus = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show system processes summary"`;
        print $currentStatus;
        @statusList = split("\n",$currentStatus);
        $line = @statusList[9];
	my @token  = split(" ", $line);
        $cpu = @token[9];
        $cpuNumeric = $cpu ;
	$cpuNumeric =~ s/\D+\z//;
        if (not $cpuNumeric){
               print"Critical:Not able to retrieve system idle CPU information";
               exit 2;
        }
        my $perfdata .= "|"
         ."idlecpu=$cpu";

        if ($cpuNumeric < 10){
                print"Critical:idle CPU usage is $cpu $perfdata";
                exit 2;
       }else{
                print"OK:idle CPU Usage is $cpu $perfdata";
                exit 0;
        }

}elsif($opt_C =~ /system_mem/){
    $currentStatus = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show system memory |match memory"`;
    @statusList = split("\n",$currentStatus);
    $cachememory = @statusList[7];
    $freememory = @statusList[8];
    my @cachetoken  = split(" ", $cachememory);
    my @freetoken  = split(" ", $freememory);
    $cache = @cachetoken[5];
    $free = @freetoken[5];
    $cache =~ s/\D+\z//;
    $free =~ s/\D+\z//;
    my $perfdata .= "|"
         ."cachememory=$cache%"
         ."freememory=$free%";

    if ($cache > 99 or $free < 1){
                print"Critical:system cache memory is $cache%, free memory is $free% $perfdata";
                exit 2;
        }else{
                print"OK:system cache memory is $cache%, free memory is $free% $perfdata";
                exit 0;
        }

}elsif($opt_C =~ /performance_session/){
    $xml = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show security monitoring performance session '|' display xml"`;
        $parser = XMLin($xml) ;
        $perf_info = $parser->{'performance-session-information'}->{'performance-session-statistics'}->{'performance-info'};
        if (not (defined $perf_info)){
               print"Critical:Not able to retrieve the number of sessions added";
               exit 2;
        }
        @statusList = split("\n",$perf_info);
        $line = @statusList[2];
        my @token  = split(" ", $line);
         my $perfdata .= "|"
         ."sessionsadded=@token[1]";
        if (@token[1] > 500000){
                print"Critical:The number of sessions added is @token[1] $perfdata";
                exit 2;
        }else{
                print"OK:The number of sessions added is @token[1] $perfdata";
                exit 0;
        }

}elsif($opt_C =~ /performance_spu/){
    $xml = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show security monitoring performance spu '|' display xml"`;
        $parser = XMLin($xml) ;
        $perf_spu = $parser->{'performance-spu-information'}->{'performance-spu-statistics'}->{'performance-info'};
        if (not (defined $perf_spu)){
               print"Critical:Not able to retrieve SPU";
               exit 2;
        }
        @statusList = split("\n",$perf_spu);
        $line = @statusList[2];
        my @token  = split(" ", $line);
        my $perfdata .= "|"
         ."SPU=@token[1]";
        if (@token[1] > 95){
                print"Critical:SPU is @token[1] $perfdata";
                exit 2;
        }else{
                print"OK:SPU is @token[1] $perfdata";
                exit 0;
        }
}elsif($opt_C =~ /activesessions/){
    $xml = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show security flow session summary '|' display xml"`;
        $parser = XMLin($xml) ;
        $active_ses = $parser->{'flow-session-summary-information'}->{'active-sessions'};
        $max_ses = $parser->{'flow-session-summary-information'}->{'max-sessions'};
        my $perfdata .= "|"
         ."activesessions=$active_ses";
        if (not (defined $active_ses)){
               print"Critical:Not able to retrieve active sessions";
               exit 2;
        }
        if ($active_ses > $max_ses ){
                print"Critical:The active sessions($active_ses) are more than max permitted sessions($max_ses) $perfdata";
                exit 2;
        }else{
                print"OK:The active sessions($active_ses) are less than max permitted sessions($max_ses) $perfdata";
                exit 0;
        }
}elsif($opt_C =~ /failedsessions/){
    $xml = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show security flow session summary '|' display xml"`;
        $parser = XMLin($xml) ;
        $failed_ses = $parser->{'flow-session-summary-information'}->{'failed-sessions'};
        my $perfdata .= "|"
         ."failedsessions=$active_ses";
        if (not (defined $failed_ses)){
               print"Critical:Not able to retrieve failed sessions";
               exit 2;
        }
        if ($failed_ses > 10000){
                print"Critical:There are $failed_ses failed sessions $perfdata";
                exit 2;
        }else{
                print"OK:There are $failed_ses failed sessions $perfdata";
                exit 0;
        }


}if($opt_C =~ /left_net_stats/){
    $xml = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show interfaces terse ge-0/0/0 '|' display xml"`;
        $parser = XMLin($xml) ;
        $ge_stats0 = $parser->{'interface-information'}->{'physical-interface'}->{'oper-status'};
        if (not $ge_stats0){
               print"Critical:Not able to retrieve the ge interface 0/0/0 status";
               exit 2;
        }
        if ($ge_stats0 ne "up"){
                print"Critical:The ge interface 0/0/0 is down";
                exit 2;
        }else{
                print"OK:The ge interface 0/0/0 is up";
                exit 0;
        }


    }elsif($opt_C =~ /left_net_input_packets/){
         $info = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show interfaces ge-0/0/0 statistics '|' display xml"`;
         $parser = XMLin($info);
         $InputPackets = $parser->{'interface-information'}->{'physical-interface'}->{'traffic-statistics'}->{'input-bps'};
         my $perfdata .= "|"
         ."left_net_input_rate(bps)=$InputPackets";
          if (not (defined  $InputPackets)){
               print "Critical:Not able to retrieve the Input Packets flow for ge interface 0/0/0";
               exit 2;
        }
        else {
            print "OK: The Input Packet rate for ge interface 0/0/0 is $InputPackets $perfdata";
            exit 0;
        }
    }elsif($opt_C =~ /left_net_output_packets/){
         $info = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show interfaces ge-0/0/0 statistics '|' display xml"`;
         $parser = XMLin($info);
         $outputPackets = $parser->{'interface-information'}->{'physical-interface'}->{'traffic-statistics'}->{'output-bps'};
         my $perfdata .= "|"
         ."left_net_output_rate(bps)=$outputPackets";
         if (not (defined $outputPackets)){
               print "Critical:Not able to retrieve the output Packets rate for ge interface 0/0/0";
               exit 2;
        }
        else {
            print "OK: The Output Packet rate for ge interface 0/0/0 is $outputPackets $perfdata";
            exit 0;
        }

############commands for ge-0/0/1 #############################

}elsif($opt_C =~ /right_net_stats/){
    $xml = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show interfaces terse ge-0/0/1 '|' display xml"`;
        $parser = XMLin($xml) ;
        $ge_stats1 = $parser->{'interface-information'}->{'physical-interface'}->{'oper-status'};
        if (not $ge_stats1){
               print"Critical:Not able to retrieve the ge interface 0/0/1 status";
               exit 2;
        }
        if ($ge_stats1 ne "up"){
                print"Critical:The ge interface 0/0/1 is down";
                exit 2;
        }else{
                print"OK:The ge interface 0/0/1 is up";
                exit 0;
        }
     }elsif($opt_C =~ /right_net_input_packets/){
         $info = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show interfaces ge-0/0/1 statistics '|' display xml"`;
         $parser = XMLin($info);
         $InputPackets = $parser->{'interface-information'}->{'physical-interface'}->{'traffic-statistics'}->{'input-bps'};
         my $perfdata .= "|"
         ."right_net_input_rate(bps)=$InputPackets";
         if (not (defined $InputPackets)){
               print "Critical:Not able to retrieve the Input Packets rate for ge interface 0/0/1";
               exit 2;
        }
        else {
            print "OK: The Input Packet rate for ge interface 0/0/0 is $InputPackets $perfdata";
            exit 0;
        }
    }elsif($opt_C =~ /right_net_output_packets/){
         $info = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show interfaces ge-0/0/1 statistics '|' display xml"`;
         $parser = XMLin($info);
         $outputPackets = $parser->{'interface-information'}->{'physical-interface'}->{'traffic-statistics'}->{'output-bps'};
         my $perfdata .= "|"
         ."right_net_output_rate(bps)=$outputPackets";
         if (not (defined $outputPackets)){
               print "Critical:Not able to retrieve the output Packets flow for ge interface 0/0/1";
               exit 2;
        }
        else {
            print "OK: The Output Packet flow for ge interface 0/0/1 is $outputPackets $perfdata";
            exit 0;
        }

}else{
        print "You must specify a check type (alarms, environment, fan, status) (-C)\n";
        exit 3;
}


#Code should not be ablt to get this far
print "The code has reached a point that should not be possible. This should be investigated.\n";
exit 3;

