#!/usr/bin/perl

#
# Google Authenticator / mod_authmemcookie Login script
# By Brad Goodman
#
# This alternate method uses mod_authmemcookie to provide cookie
# authentication through Apache. This CGI script, to which 401
# errors should be redirected, handles the authentication, and
# upon success, directly populates memcached with the login cookie
# for subsequent use.
#
# *IN PROGRESS* - currently incomplete.
# 
#

use Cache::Memcached;
use CGI qw(:standard);
use MD5;
use Digest::HMAC_SHA1 qw(hmac_sha1 hmac_sha1_hex);
use Convert::Base32;


sub hexdump($) {
	my @up = unpack("C*",shift @_);
	foreach $i (@up) {
		printf "%2.2x ",$i;
	}
	print "\n";
}

sub genCookie() {
	$memd = new Cache::Memcached {
		'servers' => ["127.0.0.1:11211"]
	};
	$value="UserName=$user\r\n";
	$value.="Groups=\r\n";
	$value.="RemoteIP=$remoteip\r\n";
	$value.="Expiration=$expires\r\n";
	$value.="Name=$name\r\n";

	$key=MD5->hexhash(rand().$$.time);

	print "Key: $key\n";

	$memd->set("test","value");
	$val = $memd->get("test");

	print ("Value is $val\n");


	$digest = hmac_sha1_hex($key,$value);
	print "Digest: $digest\n";


	$encoded = uc encode_base32("aedsfsdgf");
	print ("Encoded: $encoded\n");

	$str = pack("C*",65,66,67); # 
	print "String is $str\n";
}


sub generateCode($$) {

	my $key = shift @_;
	my $tm = shift @_;
	my $i,$offset;
	my $challenge, my $secret;
	my $hash,my @hash;

	for ($i=7;$i;$i--) {
	$challenge[$i] = $tm & 0xFF;
	$tm >>= 8;
	}

	$challenge = pack("C*",@challenge);
	$secret = decode_base32($key);

	$hash = hmac_sha1($challenge,$secret);
	@hash = unpack("C*",$hash);
	$offset = $hash[$#hash]& 0xf ;

	# Truncate Hash

	$truncatedHash=0;
	for ($i=0;$i<4;$i++) {
		$truncatedHash <<=8;
		$truncatedHash |= $hash[$offset+$i];
	}
	$truncatedHash &=0x7fffffff;
	$truncatedHash %= 1000000;
	return $truncatedHash;
}

sub lookup_user($$) {
	my $username = shift @_;
	my $password = shift @_;

	my $hashed_pw = hmac_sha1_hex($username,$password);
	return if ($username ne 'test');
	return if ($hashed_pw ne 'e518b66b3f3d684443e4f4fd6c6e745b932e99ce');
	return ("COELIIHULY64HZLL");
	
}

sub affirmcode($$$) {
	my $secret = shift @_;
	my $code = shift @_;
	my $tm = shift @_;
	my $i;

	for ($i=-1;$i<=1;$i++) {
		printf("Affirming $code vs ".generateCode($secret,$tm+$i)."\n");
		return 1 if (generateCode($secret,$tm+$i) == $code);
	}
	return 0;
}

my	$mytime = int(time/30);
my $key = "COELIIHULY64HZLL";

#print "Returned ".generateCode($key,$mytime)."\n";

if ((param('username') ne '') || (param('password') ne '') || (param('code') ne '')) {
	# Username, Password and Code given
	my $REMOTE_ADDR = $ENV{REMOTE_ADDR};
	my $secret=lookup_user(param('username'),param('password'));
	if (! defined $secret) {
		$error = "Invalid Username or Password";
	}
	elsif (affirmcode($secret,param('code'),$mytime)) {
		# Confirmed!
		print "Content-type: text/html\n\n<body>Success</body>\n";
		exit (0);
	}
		$error = "Invalid code";
} elsif (! defined $ENV{REQUEST_METHOD}) {
	print "Not HTTP\n";
	exit 0;
} 


print <<EOF
Content-type: text/html

<html>
	<head>
		<title>Login</title>
	<head>
	<body>
		<h2 style="color:#FF0000">$error</h2>
		<form>
			<table>
				<tr>
					<td>Username:</td><td><input name=username></td>
				</tr>
				<tr>
					<td>Password:</td><td><input type=password name=password></td>
				</tr>
				<tr>
					<td>Code:</td><td><input name=code></td>
				</tr>
				<tr>
					<td colspan=2><input type=submit></td>
				</tr>
			</table>
		</form>
	</body>
</html>
EOF
;

