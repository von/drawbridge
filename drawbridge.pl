#!/usr/local/bin/perl
######################################################################
#
# drawbridge.pl
#
# Short term access control system for use with TCP wrapper
#
# $Id: drawbridge.pl,v 1.1 2000/05/15 20:09:26 vwelch Exp $
#
# TODO:
#  -Make a flag for writing state file so that we only do it when we
#   have to.
#
######################################################################
#
# Constants
#

$SECONDS_PER{"SECOND"} = 1;
$SECONDS_PER{"SECONDS"} = 1;
$SECONDS_PER{"SEC"} = 1;

$SECONDS_PER{"MINUTE"} = 60;
$SECONDS_PER{"MINUTES"} = 60;
$SECONDS_PER{"MIN"} = 60;

$SECONDS_PER{"HOUR"} = 3600;
$SECONDS_PER{"HOURS"} = 3600;

$SECONDS_PER{"DAY"} = 86400;
$SECONDS_PER{"DAYS"} = 86400;

$ANY_SERVICE = "ANY";
$NO_EXPIRE_TIME = "NONE";
$UNLIMITED_CONNECTIONS = "UNLIMITED";

# Logging
$LOG_DEBUG = 1;
$LOG_INFO = 2;
$LOG_NOTICE = 3;
$LOG_WARNING = 4;
$LOG_ERR = 5;
$LOG_CRIT = 6;
$LOG_ALERT = 7;
$LOG_EMERG = 8;

#
# End Constants
#
######################################################################$
#
# Configuration parameters
#


$DRAWBRIDGE_DIR = "/usr/local/etc/drawbridge/";

# Name of the state file that drawbridge uses. Put whereever.
$DEFAULT_STATE_FILE_NAME = $DRAWBRIDGE_DIR . "drawbridge.state";
$STATE_FILE_NAME = $DEFAULT_STATE_FILE_NAME;

# Time to sleep in seconds waiting on lock file
$LOCK_SLEEP_TIME = 5;

# Default expiration time
$DEFAULT_EXPIRATION_TIME = "1 DAY";

# Default unit for time if not given on command line
$DEFAULT_TIME_UNIT = "MINUTES";

# Default number of connections
$DEFAULT_CONNECTIONS = 1;

#
# End Configuration parameters
#
######################################################################
#
# Parse command line options
# 

# Parse flags
use Getopt::Std;

getopts("f:D");

$STATE_FILE_NAME = $opt_f
    if $opt_f;

$DEBUG = $opt_D;

$CMD = shift;

if (!defined $CMD) {
    &ERR_EXIT("Command required.");
}

# Convert to upper case.
$COMMAND = $CMD;
$COMMAND =~ y/[a-z]/[A-Z]/;

######################################################################

# Current time
$CURRENT_TIME = time;


# Name of lock file
$STATE_FILE_LOCK = $STATE_FILE_NAME;
$STATE_FILE_LOCK .= ".lock";


######################################################################


if ($COMMAND eq "ALLOW") {
    &DO_ALLOW(@ARGV);

} elsif ($COMMAND eq "DELETE") {
    &DO_DELETE(@ARGV);

} elsif ($COMMAND eq "KNOCK") {
    &DO_KNOCK(@ARGV);

} elsif ($COMMAND eq "DUMP") {
    &DO_DUMP(@ARGV);

} elsif ($COMMAND eq "HELP") {
    &USAGE();
    exit 0;

} else {
    &ERR_EXIT("Unknown command \"$CMD\".");
}


exit 0;

######################################################################
######################################################################
#####
#####
##### Major Functions
#####
######################################################################
######################################################################
#
# DO_ALLOW()
#  Arguments: <options> Hostname
#  Returns: Nothing
#
# Add a number to the allowed connections for a host.
#

sub DO_ALLOW {
    # Parse flags
    getopts("ac:e:s:");

    $ADD_FLAG = $opt_a;
    $CONNECTIONS = $opt_c
	if $opt_c;
    $EXPIRE_TIME = $opt_e
	if $opt_e;
    $SERVICE = $opt_s
	if $opt_s;

    $HOST = shift(@ARGV);

    if (!defined $HOST) {
	&ERR_EXIT("Hostname required.");
    }

    print STDERR "Ignoring extra arguments.\n"
	if ($#ARGV > -1);

    # Get username for logging
    $USERNAME = getlogin || (getpwuid($<))[0] || "Unknown";

    # And expand hostname
    $HOSTNAME = &GET_FULL_HOSTNAME($HOST);

    # Set service to any if not given.
    $SERVICE = $ANY_SERVICE
	if !defined($SERVICE);

    # Set connections to 1 if not given
    $CONNECTIONS = $DEFAULT_CONNECTIONS
	if !defined($CONNECTIONS);

    # Capitialize expire time and connections
    $CONNECTIONS =~ y/[a-z]/[A-Z]/;
    $EXPIRE_TIME =~ y/[a-z]/[A-Z]/;

    # If we're not adding and the expiration time isn't set then
    # set it to the default.
    $EXPIRE_TIME = $DEFAULT_EXPIRATION_TIME
	if (!$ADD_FLAG && !defined($EXPIRE_TIME));

    # Deal with units on expiration time
    $EXPIRE_TIME = PARSE_TIME($EXPIRE_TIME);

    &LOCK_STATE_FILE();
    &READ_STATE_FILE();

    # If the entry doesn't currently exist then set the add flag to
    # zero.
    $ADD_FLAG = 0
	if !defined($ALLOW_CONN{$HOSTNAME}{$SERVICE});
		    
    if ($ADD_FLAG) {
	# Add new values to old ones
	if (!defined($CONNECTIONS) && !defined($EXPIRE_TIME)) {
	    print "Nothing to do.\n";
	    return;
	}
	
	$ALLOW_CONN{$HOSTNAME}{$SERVICE} += $CONNECTIONS
	    if defined($CONNECTIONS);

	if ($EXPIRE_TIME eq $NO_EXPIRE_TIME) {
	    $ALLOW_TIME{$HOSTNAME}{$SERVICE} = $EXPIRE_TIME;
	} else {
	    $ALLOW_TIME{$HOSTNAME}{$SERVICE} += $EXPIRE_TIME
		if defined($EXPIRE_TIME);
	}
	
    } else {
	# Set the values
	$ALLOW_CONN{$HOSTNAME}{$SERVICE} = $CONNECTIONS;

	if ($EXPIRE_TIME eq $NO_EXPIRE_TIME) {
	    $ALLOW_TIME{$HOSTNAME}{$SERVICE} = $EXPIRE_TIME;
	} else {
	    $ALLOW_TIME{$HOSTNAME}{$SERVICE} = $EXPIRE_TIME + $CURRENT_TIME;
	}
    }
		    
    # Build log string
    $LOG_STRING = "User $USERNAME set $HOSTNAME (Service $SERVICE) to ";
    $LOG_STRING .= $ALLOW_CONN{$HOSTNAME}{$SERVICE} . " connections ";
    $LOG_STRING .= "expiring ";
    $LOG_STRING .= &TIME_TO_STRING($ALLOW_TIME{$HOSTNAME}{$SERVICE});
		    
    &WRITE_STATE_FILE();

    &UNLOCK_STATE_FILE();

    &LOG($LOG_INFO, $LOG_STRING);
}
    
######################################################################
#
# DO_DELETE()
#  Arguments: Hostname
#  Returns: Nothing
#
# Delete a host from the state file. Doesn't care if it actually exists.
#

sub DO_DELETE {
    # Parse flags
    getopts("as:");

    $DELETE_ALL = $opt_a;
    $SERVICE = $opt_s;

    $HOST = shift(@ARGV);

    if (!defined $HOST) {
	&ERR_EXIT("Hostname required.");
    }

    $HOST = &GET_FULL_HOSTNAME($HOST);

    print STDERR "Ignoring extra arguments.\n"
	if ($#ARGV > -1);

    # Get username for logging
    $USERNAME = getlogin || (getpwuid($<))[0] || "Unknown";

    &LOCK_STATE_FILE();
    &READ_STATE_FILE();

    if ($DELETE_ALL) {
	# Delete everything

	if (defined($ALLOW_CONN{$HOST})) {
	    @SERVICES = keys %{$ALLOW_CONN{$HOST}};
	    
	    foreach $SERVICE (@SERVICES) {
		delete $ALLOW_CONN{$HOST}{$SERVICE};
	    }

	    $LOG_STRING = "All enteries for $HOST deleted by $USERNAME."

	}else  {
	    print "No entry for $HOST.\n";
	}
	
    } else {
	# Delete specific service
	$SERVICE = $ANY_SERVICE
	    if !defined($SERVICE);

	if (defined($ALLOW_CONN{$HOST}{$SERVICE})) {
	    delete $ALLOW_CONN{$HOST}{$SERVICE};

	    $LOG_STRING = "Entery for $HOST/$SERVICE delete by $USERNAME."

	} else {
	    print STDERR "No entry for $HOST service $SERVICE.\n";
	}
    }    

    &WRITE_STATE_FILE();
    &UNLOCK_STATE_FILE();

    &LOG($LOG_INFO, $LOG_STRING)
	if ($LOG_STRING);
}

######################################################################
#
# DO_DUMP()
#  Arguments: None
#  Returns: None
#
# Dump the state file.
#

sub DO_DUMP {
    &READ_STATE_FILE();

    @HOSTS = keys %ALLOW_CONN;

    printf "%-30s Connections    Expires\n", "Host/Service";
    print "-" x 78;
    print "\n";

    foreach $HOST (@HOSTS) {

	@SERVICES = keys %{$ALLOW_CONN{$HOST}};

	foreach $SERVICE (@SERVICES) {
	    printf("%-30s  %-9s      %s\n",
		   $HOST . "/" . $SERVICE,
		   $ALLOW_CONN{$HOST}{$SERVICE},
		   &TIME_TO_STRING($ALLOW_TIME{$HOST}{$SERVICE}));
	}
    }
    print "\n";
}


######################################################################
#
# DO_KNOCK()
#  Arguments: Hostname Service
#  Returns: Nothing
#
# Checks to see if the host is allowed to connect. It then exits
# with a code of zero if the connection is allowed and with a code
# of one if it is disallowed.
#
# Uses CHECK_HOST which will adjust the connections counter in the state
# file if appropriate.
#

sub DO_KNOCK {
    # Parse flags
    getopts("s:");

    $SERVICE = $opt_s;
    $HOST = shift(@ARGV);

    if (!defined $HOST) {
	&ERR_EXIT("Hostname required.");
    }

    $HOST = &GET_FULL_HOSTNAME($HOST);

    print STDERR "Ignoring extra arguments.\n"
	if ($#ARGV > -1);

    $SERVICE = $ANY_SERVICE
	if !defined($SERVICE);

    $ALLOWED = &CHECK_HOST($HOST, $SERVICE);

    if ($ALLOWED) {
	&LOG($LOG_INFO, "ALLOWED: $HOST $SERVICE");
    } else {
	&LOG($LOG_INFO, "DENIED: $HOST $SERVICE");
    }

    exit(!$ALLOWED);
}


######################################################################
######################################################################
#####
#####
##### State File management routines
#####
######################################################################
######################################################################
#
# READ_STATE_FILE()
#  Arguments: None
#  Returns: Nothing
#
# Reads the file specified in $STATE_FILE_NAME and defines the following
# associative arrays:
#   %ALL_CONN{}             Number of connections the host is allowed
#                           to make.
#   %ALLOW_TIME{}           Time which these connections expire.
#

sub READ_STATE_FILE {

    return
	if ( ! -e $STATE_FILE_NAME);

    if (!open(STATE_FILE, "<$STATE_FILE_NAME")) {
	return;
    }

    while(<STATE_FILE>) {
	chop;
	local($HOST, $SERVICE, $CONN, $TIME) = split;

	print "Read Host: $HOST Service: $SERVICE Conn: $CONN Time: $TIME\n"
	    if ($DEBUG);

	# Check to be sure the connection is valid
	if (($CONN ne $UNLIMITED_CONNECTIONS) && ($CONN == 0)) {
	    &LOG($LOG_DEBUG, "Ignoring entry for $HOST/$SERVICE: No connections left.");
	    next;
	}

	# Check to be sure the expiration time hasn't passed
	if (($TIME ne $NO_EXPIRE_TIME) && ($TIME < $CURRENT_TIME)) {
	    &LOG($LOG_DEBUG, "Ignoring entry for $HOST/$SERVICE: Expired.");
	    next;
	}

	$ALLOW_CONN{$HOST}{$SERVICE} = $CONN;
	$ALLOW_TIME{$HOST}{$SERVICE} = $TIME;
    }

    close(STATE_FILE);
}


######################################################################;
#
# WRITE_STATE_FILE()
#  Arguments: None
#  Returns: Nothing
#
# Writes the information in %HOST_CONNECTIONS and %HOST_TIME to the
# state file specified in $STATE_FILE_NAME.
#

sub WRITE_STATE_FILE {
    &LOG($LOG_DEBUG, "Updating state file $STATE_FILE_NAME.");

    if (!open(STATE_FILE, ">$STATE_FILE_NAME")) {
	&LOG($LOG_ERR, "Failed to write  state file \"$STATE_FILE_NAME\"");
	die "Couldn't write state file \"$STATE_FILE_NAME\".\n";
    }

    my @HOSTS = keys %ALLOW_CONN;;

    foreach $HOST (@HOSTS) {
	my @SERVICES = keys %{$ALLOW_CONN{$HOST}};

	foreach $SERVICE (@SERVICES) {
	    # We don't worry here about enteries being still valid
	    # or not. We deal with that when we read them back in.
	    print STATE_FILE $HOST . " " . $SERVICE . " " .
		$ALLOW_CONN{$HOST}{$SERVICE} . " " .
		    $ALLOW_TIME{$HOST}{$SERVICE} . "\n";
	}
    }
    
    close(STATE_FILE);
    chmod 0600, $STATE_FILE_NAME;
}

######################################################################
#
# LOCK_STATE_FILE()
#  Arguments: None
#  Returns: None
#
# Locks the state file.
#
# XXX I'm sure there are race conditions here

sub LOCK_STATE_FILE {

    # Create state file if it doesn't exist
    if (! -e $STATE_FILE_NAME) {
	open(FILE, ">$STATE_FILE_NAME");
	close(FILE);
    }

    # Assume if we can write state file we can write lock file...
    if (! -w $STATE_FILE_NAME) {
	&LOG($LOG_ERR, "Failed to lock state file \"$STATE_FILE_NAME\"");
	die "Don't have permission to lock state file.\n";
    }

    while (!symlink("$$", $STATE_FILE_LOCK)) {
	print "Waiting to acquire lock file $STATE_FILE_LOCK...\n";
	sleep $LOCK_SLEEP_TIME;
    }
}

######################################################################
#
# UNLOCK_STATE_FILE()
#  Arguments: None
#  Returns: None
#
# Unlocks the state file.
#

sub UNLOCK_STATE_FILE {
    unlink $STATE_FILE_LOCK;
}


######################################################################
######################################################################
#####
#####
##### Miscellaneous Support Routines
#####
######################################################################
######################################################################
#
# USAGE()
#  Arguments: None
#  Returns: Nothing
#
# Print Usage to STDOUT.
#
# XXX - needs to be updated.
#

sub USAGE {
    print "
Usage: $0 [global options] <command> [local options and arguments]

 Global options are:
  -f <state file>      Specify the state file to use.
                       Default is: $DEFAULT_STATE_FILE_NAME

  -D                   Debug mode

 Commands are: allow, dump

 Command specifics:

  allow <local options> <host>
     Allow <host> to connect for either a given number of connections,
     for a period of time, or both. If no arguments are given then the
     host will be allowed one connection.

     If the number of connections as set by the -c flag is the word
     \"$UNLIMITED_CONNECTIONS\" then the host will be allowed any number of connections.

     By default the the enteries for this host will expire in $DEFAULT_EXPIRATION_TIME.
     This may be changed with the -e flag.

     Local options are:

  -a                   Add the connections specified to the current number
                       the host has. Without this flag it will overwrite the
                       current value.

  -c <# connections>   Specify the number of connections to add. This value
                       is $DEFAULT_CONNECTIONS by default.

  -e <expire time>     Specify how long this entry should be valid. The default
                       unit is $DEFAULT_TIME_UNIT. A value may be specified as
                       <value> <unit>. If a unit is given as well as a value
                       then they must be quoted. Valid units are minutes,
                       hours, and days.

  -s <service>         Specify the service to allow. This may be any string
                       and is compared to the string passed to the knock
                       command. It may also be the string \"$ANY_SERVICE\"
                       in which case it will match any service.

 drawbridge delete <host>
     Delete all access permissions for <host>.

 drawbridge dump
     Show the current access permissions.

 drawbridge knock <host> <service>
     How drawbridge should be run by TCP wrapper. <host> is the connecting
     host and <service> is the daemon it is try to access.

 drawbridge help
     Print this stuff.
";
}

######################################################################
#
#
# ERR_EXIT()
#  Arguments: String
#  Returns: Doesn't
#
# Print string to STDERR and exit with code 1.
#

sub ERR_EXIT {
    my $STRING = shift;
    print STDERR $STRING . "\n";
    print STDERR "Type \"$0 help\" for help\n";
    exit 1;
}

######################################################################
#
# GET_FULL_HOSTNAME()
#  Arguments: Hostname
#  Returns: Full hostname
#
# Returns the full hostname of a given host. If the the host is unknown
# it prints an error and exits.
#

sub GET_FULL_HOSTNAME {
    local($HOSTNAME) = shift;
    local($FULLNAME);

    if (!defined $HOSTNAME) {
	return undef;
    }

    ($FULLNAME) = gethostbyname($HOSTNAME);

    if (!defined $FULLNAME) {
	&ERR_EXIT("Unknown host: \"$HOSTNAME\".");
    }
    
    return $FULLNAME;
}

######################################################################
#
# CHECK_HOST()
#  Arguments: Hostname, Service
#  Returns: 1 if host is allowed, 0 otherwise
#
# See if a host is allowed access right now, adjusting STATE enteries
# as needed.
#


sub CHECK_HOST {
    my $HOST = shift;
    my $SERVICE = shift;

    my $CODE = 0;

    return 0
	if !defined($HOST);

    $SERVICE = $ANY_SERVICE
	if !defined($SERVICE);

    &LOCK_STATE_FILE();
    &READ_STATE_FILE();
    
    if (defined($ALLOW_CONN{$HOST}{$SERVICE})) {
	if ($ALLOW_CONN{$HOST}{$SERVICE} eq $UNLIMITED_CONNECTIONS) {
	    $CODE = 1;
	} elsif ($ALLOW_CONN{$HOST}{$SERVICE} > 0) {
	    $CODE = 1;
	    $ALLOW_CONN{$HOST}{$SERVICE}--;
	}

    } elsif (defined($ALLOW_CONN{$HOST}{$ANY_SERVICE})) {
	if ($ALLOW_CONN{$HOST}{$ANY_SERVICE} eq $UNLIMITED_CONNECTIONS) {
	    $CODE = 1;
	} elsif ($ALLOW_CONN{$HOST}{$ANY_SERVICE} > 0) {
	    $CODE = 1;
	    $ALLOW_CONN{$HOST}{$ANY_SERVICE}--;
	}
    }
 	
    &WRITE_STATE_FILE();
    &UNLOCK_STATE_FILE();

    return $CODE;
}
    


######################################################################
#
# LOG
#  Arguments: Level, Message
#  Returns: Nothing
#
# Log something depending on the level. Message and subsequent arguments
# are passed through sprintf().
#
# XXX - Need to pass level through to syslog.
#


sub LOG {
    my $LEVEL = shift;
    my $FORMAT = shift;

    return
	if !defined($FORMAT);

    my $MESSAGE = sprintf($FORMAT, @_);

    if ($DEBUG) {
	print $MESSAGE . "\n";
    
    } else {

	return
	    if ($LEVEL == $LOG_DEBUG);

	system '/usr/ucb/logger', '-p', 'auth.info',
	'-t', 'drawbridge', $MESSAGE;
    }
}
    



######################################################################
#
# IS_NUMERIC
#  Arguments: String
#  Returns: 1 if string is numeric, 0 otherwise
#

sub IS_NUMERIC {
    $STRING = shift;

    return 0
	if !defined($STRING);

    return 1
	if ($STRING =~ /^[\-\+]?\d+$/);

    return 0;
}



######################################################################
#
# PARSE_TIME
#  Argument: String
#  Returns: Number of seconds
#
# Given a string with a number and a unit (anything that is a valid
# key in %SECONDS_PER) return the number of seconds.
#

sub PARSE_TIME {
    my $EXPIRE_TIME = shift;
    
    return undef
	if !defined($EXPIRE_TIME);

    return $EXPIRE_TIME
	if ($EXPIRE_TIME eq $NO_EXPIRE_TIME);

    my ($NUMBER, $UNIT) = split(/\ +/, $EXPIRE_TIME);
    my $TIME;

    if (!&IS_NUMERIC($NUMBER)) {
	&ERR_EXIT("Invalid time: \"$STRING\".");
    }

    # Convert unit to uppercase
    $UNIT =~ y/[a-z]/[A-Z]/;

    if (defined($SECONDS_PER{$UNIT})) {
	$TIME = $NUMBER * $SECONDS_PER{$UNIT};
	
    } else {
	&ERR_EXIT("Unknown unit \"$UNIT\".");
    }
    
    return $TIME;
}


######################################################################
#
# TIME_TO_STRING
#  Arguments: Number of seconds
#  Returns: String
#
# Given a time in seconds since 1970 return a string describing the time.
#

sub TIME_TO_STRING {
    my $TIME = shift;

    if (!defined($TIME)) {
	return "(null)";
    }

    if ($TIME eq $NO_EXPIRE_TIME) {
	return "NEVER";
    }

    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($TIME);

    $STRING = sprintf("%d/%d/%d ",
		     $mon + 1,
		     $mday,
		      $year);

    if ($hour > 12) {
	$STRING .= sprintf("%d:%02d PM",
		     $hour - 12,
		     $min);
    } else {
	$STRING .= sprintf("%d:%02d AM",
		     $hour,
		     $min);
    }

    return $STRING;
}
