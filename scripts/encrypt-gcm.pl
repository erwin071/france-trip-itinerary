use strict; use warnings; use MIME::Base64 qw(encode_base64);
use Math::BigInt;
my ($keyhex,$ivhex,$in,$outjson,$salt,$iter)=@ARGV;
die "args" unless $iter;
sub hex_to_bin { pack('H*', $_[0]) }
sub bin_to_hex { unpack('H*', $_[0]) }
sub aes_ecb_block {
  my ($keyhex,$block)=@_;
  open my $fh, '>', '/tmp/aes_in.bin' or die $!; binmode $fh; print $fh $block; close $fh;
  system("openssl enc -aes-256-ecb -K '$keyhex' -nopad -nosalt -in /tmp/aes_in.bin -out /tmp/aes_out.bin") == 0 or die "aes ecb failed";
  open my $of,'<','/tmp/aes_out.bin' or die $!; binmode $of; local $/; my $r=<$of>; close $of; return $r;
}
sub aes_ctr {
  my ($keyhex,$ivctrhex,$ptfile,$ctfile)=@_;
  system("openssl enc -aes-256-ctr -K '$keyhex' -iv '$ivctrhex' -nosalt -in '$ptfile' -out '$ctfile'") == 0 or die "aes ctr failed";
}
sub bi_from_bin { Math::BigInt->from_hex('0x'.unpack('H*', $_[0])) }
sub bin_from_bi { my $h=$_[0]->as_hex(); $h =~ s/^0x//; $h=('0'x(32-length($h))).$h; pack('H*',$h) }
sub gf_mul {
  my ($x,$y)=@_; my $z=Math::BigInt->new(0); my $v=$y->copy; my $R=Math::BigInt->from_hex('0xe1000000000000000000000000000000');
  for my $i (0..127){
    $z->bxor($v) if $x->copy->brsft(127-$i)->band(1)->is_one;
    if ($v->is_odd) { $v->brsft(1); $v->bxor($R); } else { $v->brsft(1); }
  }
  return $z;
}
sub ghash {
  my ($hbin,$c)=@_; my $h=bi_from_bin($hbin); my $y=Math::BigInt->new(0);
  my $padded=$c; $padded .= "\0" x ((16 - length($padded)%16)%16);
  for(my $i=0;$i<length($padded);$i+=16){ $y->bxor(bi_from_bin(substr($padded,$i,16))); $y=gf_mul($y,$h); }
  my $lenblock = pack('Q>Q>', 0, length($c)*8);
  $y->bxor(bi_from_bin($lenblock)); $y=gf_mul($y,$h);
  return bin_from_bi($y);
}
open my $pf,'<',$in or die $!; binmode $pf; local $/; my $pt=<$pf>; close $pf;
my $iv=hex_to_bin($ivhex); die "iv len" unless length($iv)==12;
my $j0=$iv."\0\0\0\1"; my $ctr=$iv."\0\0\0\2";
aes_ctr($keyhex, bin_to_hex($ctr), $in, '/tmp/gcm_ct.bin');
open my $cf,'<','/tmp/gcm_ct.bin' or die $!; binmode $cf; local $/; my $ct=<$cf>; close $cf;
my $H=aes_ecb_block($keyhex, "\0"x16);
my $S=ghash($H,$ct);
my $EJ0=aes_ecb_block($keyhex,$j0);
my $tag = $S ^ $EJ0;
my $b64ct=encode_base64($ct,''); my $b64tag=encode_base64($tag,'');
open my $oj,'>',$outjson or die $!; print $oj qq/{\n  "version": 2,\n  "alg": "AES-GCM",\n  "kdf": "PBKDF2-SHA256",\n  "iterations": $iter,\n  "salt": "$salt",\n  "iv": "$ivhex",\n  "tagLength": 128,\n  "ciphertext": "$b64ct",\n  "tag": "$b64tag"\n}\n/; close $oj;
