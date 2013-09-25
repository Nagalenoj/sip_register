#!/usr/bin/perl

use strict;

use IO::Socket::INET;
use Data::Dumper;

my ($socket, $received_data);
my ($peer_address, $peer_port);

$socket = new IO::Socket::INET (
LocalPort => '5080',
Proto => 'udp',
) or die "ERROR in Socket Creation : $!\n";

my $users = load_userlist("users.data");

while(1)
{
	my $packet = &receive();

	my $response = process_sip_packet($packet);
}

$socket->close();

sub receive
{
	my %packet;

	while(<$socket>)
	{
		chomp;

		if (/(.*?): (.*)/)
		{
			$packet{$1} = $2;
		}
		elsif (/(.*) (.*) (SIP\/.*)/)
		{
			$packet{"Type"} = $1;
			$packet{"Type-Line"} = $_;
		}
		
		last if($1 eq "Content-Length")
	}
	return \%packet;
}

sub process_sip_packet
{
	my ($data) = @_;

	if ( $data->{'Type'} eq "REGISTER" )
	{
		&process_register($data);
	}

}

sub process_register
{
#     |          REGISTER F1          |
#     |------------------------------>|
#     |      401 Unauthorized F2      |
#     |<------------------------------|
#     |          REGISTER F3          |
#     |------------------------------>|
#     |            200 OK F4          |
#     |<------------------------------|

	my ($reg_packet) = @_;

	print $socket &unauth_packet($reg_packet);

	my $packet = &receive();

	my ($username, $password) = &get_username_password($packet->{'Authorization'});
	if (exists $users->{$username} and $users->{$username} eq $password) {
		print $socket &success_packet($packet);
	}
	else  {
		print $socket &failure_packet($packet);
	}
}

sub load_userlist
{
	my ($file) = @_;
	my $fh;
	my %users;

	open $fh, "<", $file or return undef;

	foreach(<$fh>)
	{
		chomp;
		my ($user, $passwd) = split(":", $_);
		$users{$user} = $passwd;
	}
	return \%users;
}

sub get_username_password
{
	my ($data) = @_;
	
	if ($data =~ /username="(.*)".*realm="(.*)".*nonce="(.*)".*response="(.*)"/)  {
		my $user = $1;
		#Calculate md5 with nonce and realm
		my $password = "password1";

		return ($user, $password);
	}
	else  {
		return undef;
	}
}

sub unauth_packet
{
	my ($reg_packet) = @_;

	my $pkt = "SIP/2.0 401 Unauthorized
Via: $reg_packet->{'Via'}
From: $reg_packet->{'From'}
To: $reg_packet->{'To'}
Call-ID: $reg_packet->{'Call-ID'}
CSeq: $reg_packet->{'CSeq'}
WWW-Authenticate: Digest realm=\"realm.server.in\", qop=\"auth\", nonce=\"e356ry88df84\", opaque=\"\", stale=FALSE, algorithm=MD5
Content-Length: 0
";

	print $pkt;
	return $pkt;
}

sub success_packet
{
	my ($reg_packet) = @_;

	my $pkt = "SIP/2.0 200 OK
Via: $reg_packet->{'Via'}
From: $reg_packet->{'From'}
To: $reg_packet->{'To'}
Call-ID: $reg_packet->{'Call_ID'}
CSeq: $reg_packet->{'CSeq'}
Contact: $reg_packet->{'Contact'}
Content-Length: 0
";

	return $pkt;
}

sub failure_packet
{
	my ($reg_packet) = @_;

	my $pkt = "SIP/2.0 403 Forbidden
Via: $reg_packet->{'Via'}
From: $reg_packet->{'From'}
To: $reg_packet->{'To'}
Call-ID: $reg_packet->{'Call_ID'}
CSeq: $reg_packet->{'CSeq'}
Contact: $reg_packet->{'Contact'}
Content-Length: 0
";

	return $pkt;
}
