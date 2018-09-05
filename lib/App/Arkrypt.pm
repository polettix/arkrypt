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

has $_ => (is => 'rw', default => $ENV{'ARKRYPT_' . uc $_} // '')
  for qw< add_name armor digest_name force quiet squash >;

has listfile => (
   is => 'rw',
   default => $ENV{ARKRYPT_LISTFILE} // 'akt-list',
);

has recipient_aref => (
   is      => 'rw',
   default => sub { [__split_recipients($ENV{ARKRYPT_RECIPIENT})] },
);

has s3base => (
   is => 'rw',
   default => ($ENV{ARKRYPT_S3BASE} // ''),
   coerce => sub ($value) {
      return '' unless length($value // '');
      return $value =~ s{/*\z}{/}rmxs;
   },
);

has term => (
   is      => 'ro',
   lazy    => 1,
   predicate => 1,
   default => sub {
      require Term::ReadLine;
      return Term::ReadLine->new('arkrypt');
   },
);

has out => (
   is      => 'ro',
   lazy    => 1,
   default => sub ($self) {
      my $out = eval { $self->has_term && $self->term->out } || \*STDOUT;
      binmode $out, ':encoding(utf8)';
      return $out;
   },
);

########################################################################
#
# commands

sub command_decrypt ($self, @inputs) {
   ouch 400, "no input file" unless scalar @inputs;

   for my $input (@inputs) {
      my $digest = $input =~ s{\..*}{}rmxs;

      my $input_datafile = path($digest . SUFFIX_DATA);
      ouch 400, "input file $input_datafile does not exist"
        unless $input_datafile->exists;

      my $output_filename = $self->digest_name
         ? $digest . SUFFIX_PLAIN
         : $self->filename_for($digest);
      $output_filename = path($output_filename);
      $output_filename->remove
        if $output_filename->exists && $self->force;
      ouch 400, "output filename $output_filename exists"
        if $output_filename->exists;

      __run_or_die(
         [qw< gpg -o >, $output_filename, '--decrypt', $input_datafile]);
      $self->termout($output_filename);
   } ## end for my $input ($rest->@*)

   return 0;
} ## end sub command_decrypt (%config)

sub command_encrypt ($self, @inputs) {
   ouch 400, "no input file" unless scalar @inputs;

   my (@generated, $newfiles);
   try {
      my @pairs;
      for my $input (@inputs) {
         ouch 400, "invalid empty input file" unless length $input;
         $input = path($input);
         ouch 400, "invalid input file $input" unless $input->is_file;

         my $enc_filename = $self->encrypt_string_ascii("$input\n", '-');
         my $digest = PREFIX . md5_hex($enc_filename);

         my $output_data = path($digest . SUFFIX_DATA);
         if ($output_data->exists) {
            ouch 400, "target $output_data already exists"
              unless $self->force;
            $output_data->remove;
         }
         push @generated, $output_data;
         $self->encrypt_file_binary($input, $output_data);

         if ($self->add_name) {
            my $output_name = path($digest . SUFFIX_NAME);
            push @generated, $output_name;
            $output_name->spew_raw($enc_filename);
         }

         push @pairs, [$digest, $input->stringify];
      } ## end for my $input ($rest->@*)

      $newfiles = $self->add_to_list(@pairs);
   } ## end try
   catch {
      my $exception = $_;
      unlink $_ for @generated;
      die $exception;    # rethrow
   };

   $self->termout($newfiles) unless $self->quiet;
   return 0;
} ## end sub command_encrypt (%config)

sub command_filename ($self, @inputs) {
   ouch 400, 'no input filename' unless scalar @inputs;
   my $print_digest = scalar(@inputs) > 1;
   for my $name (@inputs) {
      my $filename = $self->filename_for($name);
      my $prefix = $print_digest ? "$name " : '';
      $self->termout($prefix . $filename);
   }

   return 0;
} ## end sub command_filename (%config)

sub command_interactive ($self, @rest) {
   ouch 400, 'interactive command does not accept further options'
      if scalar @rest;
   my %main_for = (
      q      => 'quit',
      bye    => 'quit',
      exit   => 'quit',
      '!ls'  => 'lls',
      ldir   => 'lls',
      '!dir' => 'lls',
      recipient => 'recipients',
      r => 'recipients',
   );
   my $term = $self->term;
   my $out  = $self->out;
   while (defined(my $line = $term->readline(PROMPT))) {
      my ($command, $rest) = $line =~ m{\A\s* (\S+) \s* (.*?) \s*\z}mxs;
      next unless defined($command) && length($command);
      if (exists $main_for{$command}) {
         $command = $main_for{$command};
      }
      elsif (defined(my $norm = $self->normal_command_name($command))) {
         $command = $norm;
      }
      try {
         my $cb = $self->can("interactive_$command")
           or ouch 400, "unknown command '$command'";
         $self->$cb($rest);
      }
      catch {
         $self->termout('error: ' . bleep);
      };
   } ## end while (defined(my $line =...))

   return 0;
} ## end sub command_interactive (%config)

sub command_list ($self, @rest) {
   # FIXME figure out what to do with @rest
   my @list = $self->load_squashed_list
     or return $self->termout('no current list');
   for my $item (@list) {
      my $digest = $item->[0];
      unshift $item->@*,
        path($digest . SUFFIX_DATA)->exists ? "\x{2714}" : ' ';
   }

   $self->termout_list(@list);
   return 0;
}

sub command_pull ($self, @queue) {
   ouch 400, "no input file" unless scalar @queue;
   my $s3base = $self->s3base
      or ouch 400, 'no s3base available for pulling files';

   my %available;
   my $list = $self->s3ls;
   for my $line (split m{\n}mxs, $list) {
      next if $line =~ m{\A \s* PRE \s}mxs;         # skip prefixes
      my (undef, undef, undef, $name) = split m{\s+}, $line, 4;
      $available{$name} = 1;
   }

   while (@queue) {
      my $input = shift @queue;
      if (!$available{$input}) {
         my $digest = $input =~ s{\..*}{}rmxs;
         my $pushed = 0;
         my @suffixes = (SUFFIX_DATA);
         push @suffixes, SUFFIX_NAME if $self->add_name;
         for my $suffix (@suffixes) {
            my $candidate = $digest . $suffix;
            next unless $available{$candidate};
            unshift @queue, $candidate;
            ++$pushed;
         } ## end for my $suffix (SUFFIX_DATA...)
         ouch 400, "inexistent file $input" unless $pushed;
         $input = shift @queue;
      } ## end if (!$available{$input...})
      ouch 400, "file $input exists locally" if -e $input && !$self->force;
      __run_or_die([qw< aws s3 cp >, "$s3base$input", '.'], undef, \*STDERR);
      $self->termout($input);
   } ## end while (@queue)

   return 0;
} ## end sub command_pull (%config)

sub command_push ($self, @queue) {
   ouch 400, "no input file" unless scalar @queue;
   my $s3base = $self->s3base
      or ouch 400, 'no s3base available for pushing files';

   while (@queue) {
      my $input = shift @queue;
      if (!-e $input) {
         my $digest = $input =~ s{\..*}{}rmxs;
         my $pushed = 0;
         my @suffixes = (SUFFIX_DATA);
         push @suffixes, SUFFIX_NAME if $self->add_name;
         for my $suffix (@suffixes) {
            my $candidate = $digest . $suffix;
            next unless -e $candidate;
            unshift @queue, $candidate;
            ++$pushed;
         } ## end for my $suffix (SUFFIX_DATA...)
         ouch 400, "inexistent file $input" unless $pushed;
         $input = shift @queue;
      } ## end if (!-e $input)
      __run_or_die([qw< aws s3 cp >, $input, $s3base], undef, \*STDERR);
      $self->termout($input);
   } ## end while (@queue)

   return 0;
} ## end sub command_push (%config)

sub command_regen ($self, @rest) {
   ouch 400, 'regen command does not accept further options'
      if scalar @rest;

   my $name_rx = join ' ',
     '(?mxs:',
     quotemeta(PREFIX),
     '.*',
     quotemeta(SUFFIX_NAME),
     ')';
   my @pairs;
   for my $file (cwd->children) {
      next unless $file->is_file;
      next unless $file =~ m{$name_rx};
      my $digest   = $file =~ s{\..*}{}rmxs;
      my $filename = $self->filename_for($file);
      push @pairs, [$digest, $filename];
   } ## end for my $file (path('.')...)

   my $listfile = $self->listfile;
   my $tmp = $listfile . '.tmp';
   rename $listfile, $tmp;
   my $list = $self->add_to_list(@pairs);
   unlink $tmp;

   $self->termout($list) unless $self->quiet;
   return 0;
} ## end sub command_regen (%config)

sub command_squash ($self, @rest) {
   ouch 400, 'squash command does not accept further options'
      if scalar @rest;

   my $listfile = $self->listfile;
   return unless -e $listfile;

   my $tmp = $listfile . '.tmp';
   rename $listfile, $tmp;
   my $list = $self->add_to_list(__split_list($self->load_list));
   unlink $tmp;

   $self->termout($list) unless $self->quiet;
   return 0;
} ## end sub command_squash (%config)

sub command_s3ls ($self) {
   my $s3base = $self->s3base
      or ouch 400, 'no s3base available for listing files';
   $self->termout($self->s3ls);
   return 0;
} ## end sub command_s3ls (%config)

########################################################################
#
# interactive commands functions

sub interactive_armor ($self, $rest) { $self->ibool(armor => $rest) }

sub interactive_aws ($self, $credentials) {
   if ($credentials) {
      @ENV{qw< AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY>} = split m{:}mxs,
        $credentials, 2;
   }
   $credentials = join ':',
     map { $_ // '' } @ENV{qw< AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY>};
   $self->termout("aws: $credentials");
} ## end sub interactive_aws

sub interactive_decrypt ($self, $rest) {
   ouch 400, 'no file to decrypt' unless length $rest;
   my @specs = __parse_line($rest);
   my $files = __resolve_list_items([$self->load_squashed_list], \@specs);
   $self->command_decrypt(map {$_->[0]} $files->@*);
} ## end sub interactive_decrypt

sub interactive_digest_name ($self, $rest) {
   $self->ibool(digest_name => $rest);
}

sub interactive_echo ($self, $rest) { $self->termout($rest) }

sub interactive_encrypt ($self, $rest) {
   ouch 400, 'no file to encrypt' unless length $rest;
   my @specs = __parse_line($rest);
   my $files = __resolve_list_items([__list_local_files()], \@specs);
   $self->command_encrypt($files->@*);
} ## end sub interactive_encrypt


sub interactive_filename ($self, $rest) {
   ouch 400, 'no input to transform into filename' unless length $rest;
   my @specs = __parse_line($rest);
   my $files = __resolve_list_items([__list_local_files()], \@specs);
   $self->command_filename($files->@*);
} ## end sub interactive_filename

sub interactive_force ($self, $rest) { $self->ibool(force => $rest) }

sub interactive_lls ($s, $r) { $s->termout_list(__list_local_files()) }

sub interactive_list ($self, $rest) { $self->command_list }

sub interactive_listfile ($self, $listfile) {
   $self->listfile($listfile) if length($listfile // '');
   $self->termout('listfile: ' . $self->listfile);
}

sub interactive_pull ($self, $rest) {
   ouch 400, 'no file to pull' unless length $rest;
   my @specs = __parse_line($rest);
   try {
      my $fs = __resolve_list_items([$self->load_squashed_list], \@specs);
      @specs = map { $_->[0] } $fs->@*;
   }
   catch {
      my $e = $_;
      die $e unless bleep =~ m{No\ secret\ key}mxs;
   };
   $self->command_pull(@specs);
} ## end sub interactive_pull

sub interactive_push ($self, $rest) {
   ouch 400, 'no file to push' unless length $rest;
   my @specs = __parse_line($rest);
   try {
      my $fs = __resolve_list_items([$self->load_squashed_list], \@specs);
      @specs = map { $_->[0] } $fs->@*;
   }
   catch {
      my $e = $_;
      die $e unless bleep($e) =~ m{No\ secret\ key}mxs;
   };
   $self->command_push(@specs);
} ## end sub interactive_push

sub interactive_quit ($self, $rest) {
   my @goodbyes = (
      'goodbye', 'bye', 'it was fun',
      'have a good day',
      'hope you enjoyed it',
      'it was nice to work together',
   );
   $self->termout($goodbyes[rand @goodbyes]);
   exit 0;
} ## end sub interactive_quit

sub interactive_recipients ($self, $line) {
   my $aref = $self->recipient_aref;
   my @rs   = $aref->@*;
   if (length $line) {
      my ($command, $rest) = $line =~ m{\A\s* (\S+) \s* (.*?) \s*\z}mxs;
      my %id_of = map { $rs[$_] => $_ } 0 .. $#rs;
      if ($command eq 'add') {
         for my $r (split m{[\s,]+}mxs, $rest) {
            next if exists $id_of{$r};
            push $aref->@*, $r;
            $id_of{$r} = scalar $aref->@*;
         }
      } ## end if ($command eq 'add')
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
            } ## end for my $r (split m{[\s+,]}mxs...)
            $aref->@* = @rs[sort { $a <=> $b } values %keep];
            $n_del = scalar(@rs) - scalar($aref->@*);
         } ## end else [ if ($rest eq '*') ]
         $self->termout(
            $n_del == 1 ? 'removed one item' : "removed $n_del items");
      } ## end elsif ($command =~ m{\A (?: del | remove | rm ) \z}mxs)
      else {
         ouch 400, "unknown recipients operation '$command'";
      }
   } ## end if (length $line)

   @rs = $aref->@*;
   if (my $n = scalar @rs) {
      $self->termout_list(@rs);
   }
   else {
      $self->termout('no recipient set');
   }

   return;
} ## end sub interactive_recipients

sub interactive_squash ($self, $rest) { $self->ibool(squash => $rest) }

sub interactive_s3base ($self, $value) {
   if (length($value //= '')) {
      $self->s3base(
         $value =~ m{\A(?:''|"")\z}mxs
         ? ''
         : $value =~ s{/*\z}{/}rmxs
      );
   } ## end if (length($value //= ...))
   $self->termout('s3base: ' . ($self->s3base // ''));
} ## end sub interactive_s3base

sub interactive_s3ls ($self, $value) { $self->command_s3ls }


########################################################################
#
# support methods

sub add_to_list ($self, @pairs) {
   @pairs = __squash_list(@pairs);
   my $mapping = join '', map { join(' ', $_->@*) . "\n" } @pairs;

   if ($self->squash) {
      my @current = __split_list($self->load_list);
      @pairs = __squash_list(@current, @pairs);
      $mapping = join '', map { join(' ', $_->@*) . "\n" } @pairs;
   } ## end if ($args->{squash})

   my $enc_mapping = $self->encrypt_string_ascii($mapping, '-');

   my $listfile = path($self->listfile);
   my $contents =
     $listfile->exists && !$self->squash ? $listfile->slurp_raw : '';
   $listfile->spew_raw($contents . $enc_mapping);

   return $mapping;
} ## end sub add_to_list

sub encrypt_file_binary ($self, $input, $output) {
   $output = path($output)->stringify;
   my $tmp    = $output . '.tmp';
   __run_or_die(
      [
         qw< gpg --trust-model always -o >,
         $tmp,
         map({ -r => $_ } $self->recipients),
         '--encrypt',
         $input,
      ]
   );
   rename $tmp, $output;
} ## end sub encrypt_file_binary (%args)

sub encrypt_string_ascii ($self, $input, $output) {
   __run_or_die(
      [
         qw< gpg -a --trust-model always -o >,
         $output,
         map({ -r => $_ } $self->recipients),
         '--encrypt',
         '-',
      ],
      $input
   );
} ## end sub encrypt_string_ascii (%args)

sub filename_for ($self, $input_name) {
   my $name      = $input_name =~ s{\..*}{}rmxs;
   my $file_name = path($name . SUFFIX_NAME);
   my $retval;
   if ($file_name->exists) {
      $retval = __run_or_die([qw< gpg -o - --decrypt >, $file_name]);
      chomp($retval);
   }
   elsif (defined(my $list = $self->load_list)) {
      for my $pair (__split_list($list)) {
         next unless $pair->[0] eq $name;
         $retval = $pair->[1];
      }
   } ## end elsif (defined(my $list =...))
   if (!defined($retval)) {
      my $datafile = $name . SUFFIX_DATA;
      if (-e $datafile) {
         $retval = $name . SUFFIX_PLAIN;
         say {*STDERR} "no filename, using default $retval";
      }
      else {
         ouch 400, "cannot find anything related to $input_name";
      }
   } ## end if (!defined($retval))
   return $retval;
} ## end sub filename_for ($input_name)

sub get_config ($self, $args) {
   my %config = ();
   GetOptionsFromArray($args, \%config, qw<
         --help --version --man --usage
         add_name|add-name|n!
         armor|a!
         aws|aws-credentials=s
         digest_name|digest-name|D!
         force|f!
         listfile|l!
         quiet|q!
         recipient|r=s@
         squash|s!
         s3base|s3-base|b=s
      >
   );

   # FIXME honor meta-options here

   # set members if so configured
   for (qw< armor digest_name force quiet squash s3base >) {
      $self->$_($config{$_} // '') if exists $config{$_};
   }
   $self->recipient_aref($config{recipient}) if exists $config{recipient};

   return $self;
} ## end sub get_config

sub has_recipients ($self) { return scalar $self->recipient_aref->@* }

sub ibool ($self, $name, $rest) {
   if (length $rest) {
      if    ($rest eq 'on')  { $self->$name(1) }
      elsif ($rest eq 'off') { $self->$name(0) }
      else { ouch 400, "$name can be set to either 'on' or 'off'" }
   }
   $self->termout($self->$name ? "$name: on" : "$name: off");
   return;
} ## end sub ibool

sub load_list ($self) {
   my $listfile = $self->listfile;
   return '' unless -e $listfile;
   scalar __run_or_die(
      [qw< gpg -o - --allow-multiple-messages --decrypt >, $listfile]);
}

sub load_squashed_list ($self) {
   defined(my $current = $self->load_list) or return;
   return __squash_list(__split_list($current));
}

sub normal_command_name ($self, $name) {
   state $main_command_for = {
      __expand_aliases(
         decrypt     => [qw< d dec >],
         encrypt     => [qw< e enc >],
         filename    => [qw< f name >],
         interactive => [qw< i int repl shell >],
         list        => [qw< l ls >],
         pull        => [qw< p get >],
         push        => [qw< P put >],
         regen       => [qw< r regen-list >],
         squash      => [qw< s squash-list >],
         s3ls        => [qw< rls >],
      )
   };
   return $main_command_for->{$name} // undef;
} ## end sub normal_command_name ($name)

sub recipient ($self) {
   my $r = $self->recipient_aref;
   ouch 400, 'no recipient set' unless $r->@*;
   return $r;
}

sub recipients ($self) { return $self->recipient->@* }

sub run ($self, @args) {
   $self = $self->new unless ref $self;
   $self->get_config(\@args);

   my $retval = try {
      my $command = shift(@args) // '';
      $command = 'interactive' unless length $command;
      my $real_command = $self->normal_command_name($command)
        or ouch 400, "unknown command '$command'";
      my $method = $self->can("command_$real_command")
        or ouch 500, "unhandled command '$command'";

      return $self->$method(@args) // 0; # return from try, not sub
   } ## end try
   catch {
      $self->termout('error: ' . bleep);
   };

   return $retval // 1;
} ## end sub run (@args)

sub s3ls ($self) {
   my $s3base = $self->s3base or ouch 400, 'no s3base set';
   return scalar __run_or_die([qw< aws s3 ls >, $s3base]);
}

sub termout ($self, $message) {
   my $out = $self->out;
   print {$out} $message;
   print {$out} "\n" unless $message =~ m{\n\z}mxs;
}

sub termout_list ($self, @list) {
   my $l = length scalar @list;
   for my $i (0 .. $#list) {
      my $item = ref($list[$i]) ? join(' ', $list[$i]->@*) : $list[$i];
      $self->termout(sprintf "%${l}d %s", $i + 1, $item);
   }
} ## end sub termout_list

sub update_members ($self, %config) {
   while (my ($key, $value) = each %config) {
      if (my $method = $self->can($key)) {
         $self->$method($value);
      }
      else {
         say {*STDERR} "unknown member '$key'";
      }
   }
   return $self;
}


########################################################################
#
# support functions

sub __expand_aliases (%aliases) {
   return map {
      my $main = $_;
      map { $_ => $main } ($main, $aliases{$main}->@*);
   } keys %aliases;
} ## end sub expand_aliases (%aliases)

sub __list_local_files {
   return sort map { $_->basename } grep { $_->is_file } cwd->children;
} ## end sub list_files

sub __parse_line ($l) {
   return substr($l, 0, 1) eq "'" ? substr($l, 1) : split m{\s+}mxs, $l;
}

sub __resolve_list_items ($list, $specs) {
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
   } ## end SPEC: for my $spec ($specs->@*)
   return [$list->@[@ids]];
} ## end sub resolve_list_items

sub __run_or_die ($command, $in = undef, $o_ref = undef, $e_ref = undef) {
   my ($out, $err);
   $err = 'see above' if $e_ref;
   IPC::Run::run($command, \$in, $o_ref // \$out, $e_ref // \$err)
     or ouch 500, "error running gpg ($?: $err)";
   return unless defined wantarray;
   return $out unless wantarray;
   return ($out, $err);
} ## end sub run_or_die

sub __split_list ($l) {
   return unless length($l // '');
   map { [split m{[ ]}mxs, $_, 2] } grep { length } split m{\n}mxs, $l;
}

sub __split_recipients ($recipients) {
   return unless length($recipients // '');
   return split m{,}mxs, $recipients;
}

sub __squash_list (@pairs) {
   my %flag;
   return reverse grep { !$flag{$_->[0]}++ } reverse @pairs;
}

1;
__END__
