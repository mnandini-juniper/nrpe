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


if($opt_C =~ /nat_config/){
    $status = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show configuration security nat"`;
    $status = "OK" ;
        if (not $status){
               print"Critical:NAT configuration is disabled $perfdata";
               exit 2;
        }else{
                print"OK:NAT configuration is enabled $perfdata";
                exit 0;
        }

}elsif($opt_C =~ /firewall_config/){
    $status = `sshpass -p "$opt_P" ssh -o StrictHostKeyChecking=no $opt_U\@$opt_H "cli show configuration firewall"`;
    if (not $status){
               print"Critical:Firewall configuration is disabled $perfdata";
               exit 2;
        }else{
                print"OK:Firewall configuration is enabled $perfdata";
                exit 0;
        }
}else{
        print "You must specify a check type (alarms, environment, fan, status) (-C)\n";
        exit 3;
}


#Code should not be ablt to get this far
print "The code has reached a point that should not be possible. This should be investigated.\n";
exit 3;
