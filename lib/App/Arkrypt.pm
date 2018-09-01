package App::Arkrypt;
use 5.024;
use warnings;
use Pod::Usage;
use Getopt::Long
  qw< GetOptionsFromArray :config gnu_getopt require_order >;
use Ouch qw< :trytiny_var >;
use Data::Dumper;
use IPC::Run;
use Path::Tiny qw< path cwd >;
use Try::Catch;
use Digest::MD5 qw< md5_hex >;
use Moo;
use experimental qw< postderef signatures >;
no warnings qw< experimental::postderef experimental::signatures >;

use constant PREFIX       => 'akt-';
use constant LISTFILE     => PREFIX . 'list';
use constant PROMPT       => 'arkrypt> ';
use constant SUFFIX_DATA  => '.data';
use constant SUFFIX_NAME  => '.name';
use constant SUFFIX_PLAIN => '.plain';

has $_ => (is => 'rw', default => $ENV{'ARKRYPT_'. uc $_})
   for qw< armor digest_name force squash s3base >;

has recipient => (
   is => 'rw',
   default => sub { [split_recipients($ENV{ARKRYPT_RECIPIENT})] },
);

sub has_recipients ($self) { return scalar $self->recipient->@* }

sub recipients ($self) {
   my $r = $self->recipient;
   ouch 400, 'no recipient set' unless $r->@*;
   return $r->@*;
}

has term => (
   is => 'ro',
   lazy => 1,
   default => sub {
      require Term::ReadLine;
      return Term::ReadLine->new('arkrypt');
   },
);

has out => (
   is => 'ro',
   lazy => 1,
   default => sub ($self) {
      my $out = eval { $self->term->out } || \*STDOUT;
      binmode $out, ':encoding(utf8)';
      return $out;
   },
);


########################################################################
#
# commands

sub command_decrypt (%config) {
   my $rest = $config{_args};
   ouch 400, "no input file" unless scalar $rest->@*;

   for my $input ($rest->@*) {
      my $digest = $input =~ s{\..*}{}rmxs;

      my $input_datafile = path($digest . SUFFIX_DATA);
      ouch 400, "input file $input_datafile does not exist"
         unless $input_datafile->exists;

      my $output_filename = path($config{digest_name}
         ? $digest . SUFFIX_PLAIN : filename_for($digest));
      $output_filename->remove
         if $output_filename->exists && $config{force};
      ouch 400, "output filename $output_filename exists"
         if $output_filename->exists;

      run_or_die(
         [ qw< gpg -o >, $output_filename, '--decrypt', $input_datafile ]);
      say {*STDOUT} $output_filename;
   }
}

sub command_encrypt (%config) {
   my $rest = $config{_args};
   ouch 400, "no input file" unless scalar $rest->@*;

   my (@generated, @pairs);
   try {
      for my $input ($rest->@*) {
         ouch 400, "invalid empty input file" unless length $input;
         $input = path($input);
         ouch 400, "invalid input file $input" unless $input->is_file;

         my $encrypted_filename = encrypt_string_ascii(
            recipient => $config{recipient},
            input  => "$input\n",
            output => '-',
         );
         my $digest = PREFIX . md5_hex($encrypted_filename);

         my $output_data = path($digest . SUFFIX_DATA);
         if ($output_data->exists) {
            ouch 400, "target $output_data already exists"
               unless $config{force};
            $output_data->remove;
         }
         my $output_name = path($digest . SUFFIX_NAME);
         push @generated, [$output_name, $output_data];

         $output_name->spew_raw($encrypted_filename);
         encrypt_file_binary(
            recipient => $config{recipient},
            input => $input,
            output => $output_data,
         );

         push @pairs, [$digest, $input->stringify];
      }
   }
   catch {
      my $exception = $_;
      for my $pair (@generated) {
         unlink $_ for $pair->@*
      }
      die $exception; # rethrow
   };

   my $newfiles = add_to_list(\%config, @pairs);
   print $newfiles unless $config{quiet};

   return 0;
};

sub command_filename (%config) {
   my $opts = $config{_args};
   ouch 400, 'no input filename' unless scalar $opts->@*;
   my $print_digest = $opts->@* > 1;
   for my $name ($opts->@*) {
      my $filename = filename_for($name);
      print {*STDOUT} "$name " if $print_digest;
      say {*STDOUT} $filename;
   }
}

sub command_interactive (%config) {
   my $self = __PACKAGE__->new(%config);
   my %main_for = (
      q => 'quit',
      bye => 'quit',
      exit => 'quit',
      '!ls' => 'lls',
   );
   my $term = $self->term;
   my $out  = $self->out;
   while (defined(my $line = $term->readline(PROMPT))) {
      my ($command, $rest) = $line =~ m{\A\s* (\S+) \s* (.*?) \s*\z}mxs;
      next unless defined ($command) && length($command);
      if (exists $main_for{$command}) {
         $command = $main_for{$command};
      }
      elsif (defined(my $norm = normal_command_name($command))) {
         $command = $norm;
      }
      try {
         my $cb = $self->can("interactive_$command")
            or ouch 400, "unknown command '$command'";
         $self->$cb($rest);
      }
      catch {
         $self->termout(bleep);
      };
   }
}

sub command_list (%config) {
   defined(my $list = load_list()) or return;
   print $list;
}

sub command_pull (%config) {
   my $rest = $config{_args};

   ouch 400, 'no s3base available for pulling files'
      unless length($config{s3base} // '');
   my $s3base = $config{s3base} =~ s{/*\z}{/}rmxs; # ensure one trailing /

   my @queue = $rest->@*;
   ouch 400, "no input file" unless scalar @queue;

   my %available;
   my $list = s3ls($s3base);
   for my $line (split m{\n}mxs, $list) {
      next if $line =~ m{\A \s* PRE \s}mxs; # skip prefixes
      my (undef, undef, undef, $name) = split m{\s+}, $line, 4;
      $available{$name} = 1;
   }

   while (@queue) {
      my $input = shift @queue;
      if (!$available{$input}) {
         my $digest = $input =~ s{\..*}{}rmxs;
         my $pushed = 0;
         for my $suffix (SUFFIX_DATA, SUFFIX_NAME) {
            my $candidate = $digest . $suffix;
            next unless $available{$candidate};
            unshift @queue, $candidate;
            ++$pushed;
         }
         ouch 400, "inexistent file $input" unless $pushed;
         $input = shift @queue;
      }
      ouch 400, "file $input exists locally"
         if -e $input && !$config{force};
      run_or_die([qw< aws s3 cp >, "$s3base$input", '.'], undef, \*STDERR);
      say {*STDOUT} $input;
   }
   return 0;
}

sub command_push (%config) {
   my $rest = $config{_args};

   ouch 400, 'no s3base available for pushing files'
      unless length($config{s3base} // '');
   my $s3base = $config{s3base} =~ s{/*\z}{/}rmxs; # ensure one trailing /

   my @queue = $rest->@*;
   ouch 400, "no input file" unless scalar @queue;

   while (@queue) {
      my $input = shift @queue;
      if (! -e $input) {
         my $digest = $input =~ s{\..*}{}rmxs;
         my $pushed = 0;
         for my $suffix (SUFFIX_DATA, SUFFIX_NAME) {
            my $candidate = $digest . $suffix;
            next unless -e $candidate;
            unshift @queue, $candidate;
            ++$pushed;
         }
         ouch 400, "inexistent file $input" unless $pushed;
         $input = shift @queue;
      }
      run_or_die([qw< aws s3 cp >, $input, $s3base], undef, \*STDERR);
      say {*STDOUT} $input;
   }
   return 0;
}

sub command_regen (%config) {
   my $name_rx = join ' ',
      '(?mxs:',
      quotemeta(PREFIX),
      '.*',
      quotemeta(SUFFIX_NAME),
      ')';
   my @pairs;
   for my $file (path('.')->children) {
      next unless $file->is_file;
      next unless $file =~ m{$name_rx};
      my $digest = $file =~ s{\..*}{}rmxs;
      my $filename = filename_for($file);
      push @pairs, [$digest, $filename];
   }

   path(LISTFILE)->remove;
   my $list = add_to_list(\%config, @pairs);
   print $list unless $config{quiet};

   return 0;
}

sub command_squash (%config) {
   defined(my $current = load_list()) or return 0;
   path(LISTFILE)->remove;
   my $list = add_to_list(\%config, squash_list(split_list($current)));
   print $list unless $config{quiet};
   return 0;
}

sub command_s3ls (%config) {
   ouch 400, 'no s3base available for pulling files'
      unless length($config{s3base} // '');
   my $s3base = $config{s3base} =~ s{/*\z}{/}rmxs; # ensure one trailing /

   print {*STDOUT} s3ls($s3base);
}


########################################################################
#
# interactive commands functions

sub _ibool ($self, $name, $rest) {
   if (length $rest) {
      if ($rest eq 'on') { $self->$name(1) }
      elsif ($rest eq 'off') { $self->$name(0) }
      else { ouch 400, "$name can be set to either 'on' or 'off'" }
   }
   $self->termout($self->$name ? "$name: on" : "$name: off");
   return;
}

sub interactive_armor ($self, $rest) { $self->_ibool(armor => $rest) }

sub interactive_aws ($self, $credentials) {
   if ($credentials) {
      @ENV{qw< AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY>}
         = split m{:}mxs, $credentials, 2;
   }
   $credentials = join ':', map { $_ // '' }
      @ENV{qw< AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY>};
   $self->termout("aws: $credentials");
}

sub interactive_decrypt ($self, $rest) {
   ouch 400, 'no file to decrypt' unless length $rest;
   my @specs = substr($rest, 0, 1) eq "'" ? substr($rest, 1)
      : split m{\s+}mxs, $rest;
   my $files = resolve_list_items([$self->load_squashed_list], \@specs);
   command_decrypt(
      _args => [map {$_->[0]} $files->@*],
      digest_name => ($self->digest_name // 0),
      force => ($self->force // 0),
   );
}

sub interactive_digest_name ($self, $rest) {
   $self->_ibool(digest_name => $rest);
}

sub interactive_echo ($self, $rest) { $self->termout($rest) }

sub interactive_encrypt ($self, $rest) {
   ouch 400, 'no file to encrypt' unless length $rest;

   my @recipients = $self->recipients;

   my @specs = substr($rest, 0, 1) eq "'" ? substr($rest, 1)
      : split m{\s+}mxs, $rest;
   my $files = resolve_list_items([list_files()], \@specs);

   command_encrypt(
      armor => ($self->armor // 0),
      force => ($self->force // 0),
      recipient => \@recipients,
      squash => ($self->squash // 0),
      _args => $files, # restrict to selected
   );
}

sub old_resolve_list_items ($list, $specs) {
   my %flag;
   my %id_of = map { $list->[$_] => $_ } 0 .. $#$list;
   my @ids;
   for my $item ($specs->@*) {
      if (defined(my $id = $id_of{$item})) {
         push @ids, $id unless $flag{$id}++;
      }
      elsif ($item =~ m{\A [1-9]\d* \z}mxs) {
         my $id = $item - 1;
         push @ids, $id unless $flag{$id}++;
      }
      else {
         ouch 400, "no such element or id '$item'";
      }
   }
   return [$list->@[@ids]];
}

sub resolve_list_items ($list, $specs) {
   my @id_of;
   for my $idx (0 .. $#$list) {
      my $item = $list->[$idx];
      my @items = ref($item) ? $item->@* : $item;
      $id_of[$_]{$items[$_]} = $idx for 0 .. $#items;
   }
   my (@ids, %flag);
   SPEC:
   for my $spec ($specs->@*) {
      for my $iof (@id_of) {
         defined(my $id = $iof->{$spec}) or next;
         push @ids, $id unless $flag{$id}++;
         next SPEC;
      }
      if ($spec =~ m{\A [1-9]\d* \z}mxs) {
         my $id = $spec - 1;
         push @ids, $id unless $flag{$id}++;
         next SPEC;
      }
      ouch 400, "no such element or id '$spec'";
   }
   return [$list->@[@ids]];
}

sub interactive_filename ($self, $rest) {
   my @specs = substr($rest, 0, 1) eq "'" ? substr($rest, 1)
      : split m{\s+}mxs, $rest;
   my $files = resolve_list_items([list_files()], \@specs);
   command_filename(_args => $files);
}

sub interactive_force ($self, $rest) { $self->_ibool(force => $rest) }

sub list_files {
   my $cwd = cwd;
   return sort { $a cmp $b } map {$_->basename} grep { $_->is_file }
      $cwd->children;
}

sub interactive_lls ($self, $rest) { $self->termout_list(list_files()) }

sub load_squashed_list ($self) {
   defined(my $current = load_list()) or return;
   return squash_list(split_list($current));
}

sub interactive_list ($self, $rest) {
   my @list = $self->load_squashed_list
      or return $self->termout('no current list');
   for my $item (@list) {
      my $digest = $item->[0];
      unshift $item->@*, path($digest . SUFFIX_DATA)->exists ? "\x{2714}" : ' ';
   }
   $self->termout_list(@list);
}

sub termout_list ($self, @list) {
   my $l = length scalar @list;
   for my $i (0 .. $#list) {
      my $item = ref($list[$i]) ? join(' ', $list[$i]->@*) : $list[$i];
      $self->termout(sprintf "%${l}d %s", $i + 1, $item);
   }
}

sub interactive_pull ($self, $rest) {
   ouch 400, 'no file to pull' unless length $rest;
   my @specs = substr($rest, 0, 1) eq "'" ? substr($rest, 1)
      : split m{\s+}mxs, $rest;
   my $files = resolve_list_items([$self->load_squashed_list], \@specs);
   my @digests = map {$_->[0]} $files->@*;
   command_pull(
      _args => \@digests,
      force => ($self->force // 0),
      s3base => $self->s3base,
   );
}

sub interactive_push ($self, $rest) {
   ouch 400, 'no file to push' unless length $rest;
   my @specs = substr($rest, 0, 1) eq "'" ? substr($rest, 1)
      : split m{\s+}mxs, $rest;
   my $files = resolve_list_items([$self->load_squashed_list], \@specs);
   my @digests = map {$_->[0]} $files->@*;
   command_push(
      _args => \@digests,
      s3base => $self->s3base,
   );
}

sub interactive_quit ($self, $rest) {
   my @goodbyes = (
      'goodbye',
      'bye',
      'it was fun',
      'have a good day',
      'hope you enjoyed it',
      'it was nice to work together',
   );
   $self->termout($goodbyes[rand @goodbyes]);
   exit 0;
}

sub interactive_recipients ($self, $line) {
   my $aref = $self->recipient;
   my @rs = $aref->@*;
   if (length $line) {
      my ($command, $rest) = $line =~ m{\A\s* (\S+) \s* (.*?) \s*\z}mxs;
      my %id_of = map { $rs[$_] => $_ } 0 .. $#rs ;
      if ($command eq 'add') {
         for my $r (split m{[\s,]+}mxs, $rest) {
            next if exists $id_of{$r};
            push $aref->@*, $r;
            $id_of{$r} = scalar $aref->@*;
         }
      }
      elsif ($command =~ m{\A (?: del | remove | rm ) \z}mxs) {
         my $n_del;
         if ($rest eq '*') {
            ($n_del, $aref->@*) = (scalar $aref->@*);
         }
         else {
            my %keep = %id_of;
            for my $r (split m{[\s+,]}mxs, $rest) {
               if (exists $id_of{$r}) {
                  delete $keep{$r};
               }
               elsif ($r =~ m{\A [1-9]\d* \z}mxs && $r <= scalar @rs) {
                  delete $keep{$rs[$r - 1]};
               }
               else {
                  ouch 400, "unknown addres or id '$r'";
               }
            }
            $aref->@* = @rs[sort {$a <=> $b} values %keep];
            $n_del = scalar(@rs) - scalar($aref->@*);
         }
         $self->termout($n_del == 1 ? 'removed one item' : "removed $n_del items");
      }
      else {
         ouch 400, "unknown recipients operation '$command'";
      }
   }

   @rs = $aref->@*;
   if (my $n = scalar @rs) {
      $self->termout_list(@rs);
   }
   else {
      $self->termout('no recipient set');
   }

   return;
}

sub interactive_squash ($self, $rest) { $self->_ibool(squash => $rest) }

sub interactive_s3base ($self, $value) {
   if (length($value //= '')) {
      $self->s3base($value =~ m{\A(?:''|"")\z}mxs ? ''
         : $value =~ s{/*\z}{/}rmxs);
   }
   $self->termout('s3base: ' . ($self->s3base // ''));
}

sub interactive_s3ls ($self, $value) {
   command_s3ls(s3base => scalar($self->s3base));
}

sub termout ($self, $message) {
   my $out = $self->out;
   say {$out} $message;
}


########################################################################
#
# support functions

sub handle_for ($value, $mode) {
   return (IO::File->new($mode, $value, ':raw'), 1) if defined $value;
   return (IO::Handle->new, 0);
}

sub run_or_die ($command, $in = undef, $out_ref = undef, $err_ref = undef) {
   my ($out, $err);
   $err = 'see above' if $err_ref;
   IPC::Run::run($command, \$in, $out_ref // \$out, $err_ref // \$err)
      or ouch 500, "error running gpg ($?: $err)";
   return unless defined wantarray;
   return $out unless wantarray;
   return ($out, $err);
}

sub encrypt_string_ascii (%args) {
   run_or_die(
      [
         qw< gpg -a --trust-model always -o >, $args{output},
         map({; '-r' => $_ } $args{recipient}->@*),
         '--encrypt', '-',
      ],
      $args{input}
   );
}

sub encrypt_file_binary (%args) {
   my $output = $args{output}->stringify;
   my $tmp = $output . '.tmp';
   run_or_die(
      [
         qw< gpg --trust-model always -o >, $tmp,
         map({; '-r' => $_ } $args{recipient}->@*),
         '--encrypt', $args{input},
      ]
   );
   rename $tmp, $output;
}

sub squash_list (@pairs) {
   my %flag;
   return reverse grep { !$flag{$_->[0]}++ } reverse @pairs;
}

sub add_to_list ($args, @pairs) {
   @pairs = squash_list(@pairs);
   my $mapping = join '', map { join(' ', $_->@*) . "\n" } @pairs;

   if ($args->{squash}) {
      my $current = load_list() // '';
      unshift @pairs, split_list($current) if length $current;
      @pairs = squash_list(@pairs);
      $mapping = join '', map { join(' ', $_->@*) . "\n" } @pairs;
   }

   my $enc_mapping = encrypt_string_ascii(
      recipient => $args->{recipient},
      input => $mapping,
      output => '-',
   );

   my $listfile = path(LISTFILE);
   my $contents = $listfile->exists && ! $args->{squash}
      ? $listfile->slurp_raw : '';
   $listfile->spew_raw($contents . $enc_mapping);

   return $mapping;
}

sub load_list {
   return unless -e LISTFILE;
   run_or_die(
      [ qw< gpg -o - --allow-multiple-messages --decrypt >, LISTFILE ]);
}

sub split_list ($current) {
   map { [ split m{[ ]}mxs, $_, 2 ] }
      grep { length } split m{\n}mxs, $current;
}

sub filename_for ($input_name) {
   my $name = $input_name =~ s{\..*}{}rmxs;
   my $file_name = path($name . SUFFIX_NAME);
   my $retval;
   if ($file_name->exists) {
      $retval = run_or_die([ qw< gpg -o - --decrypt >, $file_name ]);
      chomp($retval);
   }
   elsif (defined(my $list = load_list())) {
      for my $pair (split_list($list)) {
         next unless $pair->[0] eq $name;
         $retval = $pair->[1];
      }
   }
   if (! defined($retval)) {
      my $datafile = $name . SUFFIX_DATA;
      if (-e $datafile) {
         $retval = $name . SUFFIX_PLAIN;
         say {*STDERR} "no filename, using default $retval";
      }
      else {
         ouch 400, "cannot find anything related to $input_name";
      }
   }
   return $retval;
}

sub s3ls ($s3base) { run_or_die([qw< aws s3 ls >, $s3base]) }

sub error ($message) {
   print {*STDERR} "$message\n";
}

sub run (@args) {
   shift @args if @args && $args[0] eq __PACKAGE__;
   my ($config, $rest) = get_config('' => \@args);

   my $retval = try {
      my $command = shift($rest->@*) // 'interactive';
      ouch 400, 'no command provided' unless length $command;
      my $real_command = normal_command_name($command)
         or ouch 400, "unknown command '$command'";
      my $command_sub = __PACKAGE__->can("command_$real_command")
         or ouch 500, "unhandled command '$command'";

      # parse options, so that the callback receives parsed stuff and
      # is more easily reusable
      my ($cmd_config, $cmd_rest) = get_config($real_command, $rest);
      return $command_sub->(
         $config->%*,
         $cmd_config->%*,
         _args       => $cmd_rest,
         _config     => $config,
         _cmd_config => $cmd_config,
      ) // 0;
      # this return is from the "try", not from the sub
   }
   catch {
      error(bleep);
   };

   return $retval // 1;
}

sub normal_command_name ($name) {
   state $main_command_for = {
      expand_aliases(
         decrypt  => [qw< d dec >],
         encrypt  => [qw< e enc >],
         filename => [qw< f name >],
         interactive => [qw< i int repl shell >],
         list     => [qw< l ls >],
         pull     => [qw< p get >],
         push     => [qw< P put >],
         regen    => [qw< r regen-list >],
         squash   => [qw< s squash-list >],
         s3ls     => [qw< rls >],
      )
   };
   return $main_command_for->{$name} // undef;
}

sub get_config($command, $args) {
   state $spec_for = {
      armor => {
         spec => 'armor|a!',
         default => $ENV{ARKRYPT_ARMOR},
      },
      digest_name => {
         spec => 'digest_name|digest-name|D!',
         default => $ENV{ARKRYPT_DIGEST_NAME},
      },
      force => {
         spec => 'force|f!',
         default => $ENV{ARKRYPT_FORCE},
      },
      quiet => {
         spec => 'quiet|q!',
         default => $ENV{ARKRYPT_QUIET},
      },
      s3base => {
         spec => 's3base|s3-base|b=s',
         default => $ENV{ARKRYPT_S3BASE},
      },
      recipient => {
         spec => 'recipient|r=s@',
         default => [split_recipients($ENV{ARKRYPT_RECIPIENT})],
      },
      squash => {
         spec => 'squash|s!',
         default => $ENV{ARKRYPT_SQUASH},
      },
   };
   state $options_for = {
      '' => [
         qw< --help --version --man --usage >,
      ],
      decrypt => [
         $spec_for->@{qw< digest_name force >},
      ],
      encrypt => [
         $spec_for->@{qw< armor force quiet recipient squash >},
      ],
      interactive => [
         $spec_for->@{qw< armor digest_name force recipient squash s3base >},
      ],
      pull => [ $spec_for->@{qw< force quiet s3base >}, ],
      push => [ $spec_for->@{qw< quiet s3base >}, ],
      regen => [ $spec_for->@{qw< quiet recipient >}, ],
      squash => [ $spec_for->@{qw< quiet recipient >}, ],
      s3ls => [ $spec_for->@{qw< s3base >}, ],
   };

   return({}, $args) unless exists $options_for->{$command};

   my %default_for;
   my @options = map {
      if (! ref $_) { $_ }
      else {
         my $spec = $_->{spec};
         my $name = $spec =~ s{\|.*}{}rmxs;
         $default_for{$name} = $_->{default} if exists $_->{default};
         $spec;
      }
   } $options_for->{$command}->@*;
   my %config;
   GetOptionsFromArray($args, \%config, @options);
   return({%default_for, %config}, $args);
}

sub split_recipients ($recipients) {
   return unless length($recipients // '');
   return split m{,}mxs, $recipients;
}

sub expand_aliases (%aliases) {
   return map {
      my $main = $_;
      map { $_ => $main } ($main, $aliases{$main}->@*);
   } keys %aliases;
}

1;
__END__
