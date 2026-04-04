#!/usr/bin/env perl
use strict;
use warnings;
use Socket qw(inet_aton);

sub read_varint {
    my ($fh) = @_;
    my ($result, $shift) = (0, 0);
    while (1) {
        read($fh, my $byte, 1) or die "EOF";
        my $b = ord($byte);
        $result |= ($b & 0x7F) << $shift;
        return $result unless $b & 0x80;
        $shift += 7;
    }
}

sub read_str {
    my ($fh) = @_;
    read($fh, my $len, 1);
    $len = ord($len);
    read($fh, my $s, $len);
    return $s;
}

sub load {
    my ($path) = @_;
    $path //= "blocklist.bin";
    open my $fh, '<:raw', $path or die "Cannot open $path: $!";

    read($fh, my $magic, 4);
    die "invalid magic" unless $magic eq "IPBL";
    read($fh, my $ver, 1);
    die "bad version" unless ord($ver) == 2;
    read($fh, my $ts, 4);
    my $timestamp = unpack("V", $ts);

    read($fh, my $fc, 1);
    my @flags = map { read_str($fh) } 1..ord($fc);
    read($fh, my $cc, 1);
    my @cats = map { read_str($fh) } 1..ord($cc);

    read($fh, my $fcnt, 2);
    my $feed_count = unpack("v", $fcnt);
    my @feeds;

    for (1..$feed_count) {
        my $name = read_str($fh);
        read($fh, my $bsco, 2);
        my ($bs, $co) = unpack("CC", $bsco);
        read($fh, my $fmbin, 4);
        my $fm = unpack("V", $fmbin);
        read($fh, my $cmbin, 1);
        my $cm = ord($cmbin);
        read($fh, my $rcbin, 4);
        my $rc = unpack("V", $rcbin);

        my (@v4s, @v4e);
        my $current = 0;
        for (1..$rc) {
            $current += read_varint($fh);
            my $size = read_varint($fh);
            my $end = $current + $size;
            if ($end <= 0xFFFFFFFF) {
                push @v4s, $current;
                push @v4e, $end;
            }
        }

        my @mf = grep { $fm & (1 << $_) } 0..$#flags;
        my @mc = grep { $cm & (1 << $_) } 0..$#cats;

        push @feeds, {
            name => $name, bs => $bs, co => $co,
            flags => [map { $flags[$_] } @mf],
            cats => [map { $cats[$_] } @mc],
            v4s => \@v4s, v4e => \@v4e,
        };
    }
    close $fh;
    return ($timestamp, \@feeds);
}

sub bisect_right {
    my ($arr, $target) = @_;
    my ($lo, $hi) = (0, scalar @$arr);
    while ($lo < $hi) {
        my $mid = int(($lo + $hi) / 2);
        if ($arr->[$mid] <= $target) { $lo = $mid + 1 }
        else { $hi = $mid }
    }
    return $lo;
}

sub ipv4_to_int {
    my $packed = inet_aton($_[0]) or return undef;
    return unpack("N", $packed);
}

die "Usage: perl lookup.pl <ip> [<ip> ...]\n" unless @ARGV;

my ($timestamp, $feeds) = load();

for my $ip (@ARGV) {
    my $target = ipv4_to_int($ip);
    unless (defined $target) {
        print "$ip: invalid/unsupported IP\n"; next;
    }

    my $found = 0;
    for my $f (@$feeds) {
        my $idx = bisect_right($f->{v4s}, $target) - 1;
        if ($idx >= 0 && $target <= $f->{v4e}[$idx]) {
            my $score = ($f->{bs} / 200.0) * ($f->{co} / 200.0);
            my @parts = ($f->{name}, sprintf("score=%.2f", $score));
            push @parts, "flags=" . join(",", @{$f->{flags}})
                if @{$f->{flags}};
            push @parts, "cats=" . join(",", @{$f->{cats}})
                if @{$f->{cats}};
            printf "%s: %s\n", $ip, join(" | ", @parts);
            $found = 1;
        }
    }
    print "$ip: no matches\n" unless $found;
}
