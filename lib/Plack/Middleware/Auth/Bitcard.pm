package Plack::Middleware::Auth::Bitcard;

use v5.008;
use strict;
use warnings;

BEGIN {
	$Plack::Middleware::Auth::Bitcard::AUTHORITY = 'cpan:TOBYINK';
	$Plack::Middleware::Auth::Bitcard::VERSION   = '0.001';
}

use Carp;
use JSON qw(to_json from_json);
use Plack::Response;
use Plack::Request;
use Plack::Util;
use Plack::Util::Accessor qw(bitcard);
use Digest::SHA qw(sha1_hex);

use base "Plack::Middleware";

sub prepare_app
{
	my $self = shift;
	croak "Need to provide Authen::Bitcard object" unless ref $self->bitcard;
	$self->bitcard->info_required('username');
}

sub call
{
	my $self = shift;
	my $env  = $_[0];
	my $req  = "Plack::Request"->new($env);
	
	if ($self->_req_is_boomerang($req))
	{
		my $res = $self->_store_cookie_data($req);
		return $res->finalize;
	}
	elsif ($self->_fetch_cookie_data($req => $env))
	{
		return $self->app->($env);
	}
	else
	{
		my $res = $self->_start_boomerang($req);
		return $res->finalize;
	}
}

sub _boomerang_uri
{
	my $self = shift;
	my $req  = $_[0];
	
	my $base = $req->base;
	$base =~ m{/$} ? "${base}_bitcard_boomerang" : "${base}/_bitcard_boomerang";
}

sub _start_boomerang
{
	my $self = shift;
	my $req  = $_[0];
	
	my $res = "Plack::Response"->new;
	$res->cookies->{bitcard_return_to} = $req->uri;
	$res->redirect(
		$self->bitcard->login_url(
			r => $self->_boomerang_uri($req),
		),
	);
	return $res;
}

sub _req_is_boomerang
{
	my $self = shift;
	my $req  = $_[0];
	
	my ($uri) = split /\?/, $req->uri;  # ignore query string
	return ($uri eq $self->_boomerang_uri($req));
}

sub _store_cookie_data
{
	my $self = shift;
	my $req  = $_[0];
	
	my $user = $self->bitcard->verify($req);
	$user->{_checksum} = sha1_hex($self->bitcard->api_secret . $user->{username});
	
	my $res = "Plack::Response"->new;
	$res->redirect($req->cookies->{bitcard_return_to} || $req->base);
	$res->cookies->{bitcard} = to_json($user);
	$req->cookies->{bitcard_return_to} = { value => "0" };
	return $res;
}

sub _fetch_cookie_data
{
	my $self = shift;
	my ($req, $env) = @_;

	return unless $req->cookies->{bitcard};
	my $user = from_json($req->cookies->{bitcard});

	return unless sha1_hex($self->bitcard->api_secret . $user->{username}) eq $user->{_checksum};

	$env->{BITCARD} = +{%$user};
	delete $env->{BITCARD}{_checksum};
	return $env->{BITCARD};
}

1;

__END__

=pod

=encoding utf-8

=head1 NAME

Plack::Middleware::Auth::Bitcard - Bitcard authentication for Plack, which I suppose is what you might have guessed from the name

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 BUGS

Please report any bugs to
L<http://rt.cpan.org/Dist/Display.html?Queue=Plack-Middleware-Auth-Bitcard>.

=head1 SEE ALSO

=head1 AUTHOR

Toby Inkster E<lt>tobyink@cpan.orgE<gt>.

=head1 COPYRIGHT AND LICENCE

This software is copyright (c) 2013 by Toby Inkster.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.


=head1 DISCLAIMER OF WARRANTIES

THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.

