# #!/usr/bin/python

import fcntl
import os
import sys
import signal
import resource
import logging
import atexit
from logging import handlers


class Daemonize(object):
    """ Daemonize object
    Object constructor expects three arguments:
    - app: contains the application name which will be sent to syslog.
    - pid: path to the pidfile.
    - action: your custom function which will be executed after daemonization.
    - keep_fds: optional list of fds or file paths which should not be closed.
    - close_fds: optional list of fds or file paths which should be closed. (not to be
      used with keep_fds). If close_fds is specified, only those fds will be closed. 
      Otherwise, all open files will be closed (except ones specified by keep_fds)
    """
    def __init__(self, app, pid, action, logger=None, keep_fds=[], close_fds=[]):
        self.app = app
        self.pid = pid
        self.action = action
        self.keep_fds = keep_fds if keep_fds else []
        self.close_fds = close_fds if close_fds else []
        
        if len(self.keep_fds) > 0 and len(self.close_fds) > 0:
            raise ValueError("keep_fds and close_fds are mutually exclusive")
        
        # Initialize logging.
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger(self.app)
            self.logger.setLevel(logging.DEBUG)
            # Display log messages only on defined handlers.
            self.logger.propagate = False
            # It will work on OS X and Linux. No FreeBSD support, guys, I don't want to import re here
            # to parse your peculiar platform string.
            if sys.platform == "darwin":
                syslog_address = "/var/run/syslog"
            else:
                syslog_address = "/dev/log"
            syslog = handlers.SysLogHandler(syslog_address)
            syslog.setLevel(logging.INFO)
            # Try to mimic to normal syslog messages.
            formatter = logging.Formatter("%(asctime)s %(name)s: %(message)s",
                                          "%b %e %H:%M:%S")
            syslog.setFormatter(formatter)
            self.logger.addHandler(syslog)
            
        self.file_mapping = {}
        for fd in os.listdir('/proc/self/fd'):
            fd = int(fd)
            try:
                fdpath = os.readlink('/proc/self/fd/%s' % fd)
                if fdpath != '/proc/self/fd':
                    self.file_mapping[fdpath] = fd
            except:
                pass

    def sigterm(self, signum, frame):
        """ sigterm method
        These actions will be done after SIGTERM.
        """
        self.logger.warn("Caught signal %s. Stopping daemon." % signum)
        os.remove(self.pid)
        sys.exit(0)
        
    # Convert all paths to file descriptors and remove non existing paths
    def clean_list(self, files):      
        # Iterate backwards to allow in-place modification of list
        for i in reversed(range(len(files))):
            file = files[i]
            if type(file) is str:
                fd = self.file_mapping.get(file)
                if fd:
                    files[i] = fd
                else:
                    del files[i] # If not found, remove from list
    
    def start(self):
        """ start method
        Main daemonization process.
        """
        # Fork, creating a new process for the child.
        process_id = os.fork()
        if process_id < 0:
            # Fork error. Exit badly.
            sys.exit(1)
        elif process_id != 0:
            # This is the parent process. Exit.
            sys.exit(0)
        # This is the child process. Continue.

        # Stop listening for signals that the parent process receives.
        # This is done by getting a new process id.
        # setpgrp() is an alternative to setsid().
        # setsid puts the process in a new parent group and detaches its controlling terminal.
        process_id = os.setsid()
        if process_id == -1:
            # Uh oh, there was a problem.
            sys.exit(1)

        # Close all file descriptors, except the ones mentioned in self.keep_fds.
        devnull = "/dev/null"
        if hasattr(os, "devnull"):
            # Python has set os.devnull on this system, use it instead as it might be different
            # than /dev/null.
            devnull = os.devnull


        # If the user supplied values to close_fds, then we will only close those.
        # Else, we will 'automatically' close all available fds.
        # Need to check here because clean_list might remove specified paths if they 
        # don't exist and bring the lists length to 0 (when the user was still 
        # intending for not every fd to be closed automatically
        automatic_close = len(self.close_fds) == 0
    
        self.clean_list(self.close_fds)
        self.clean_list(self.keep_fds)
        self.closed = set()
    
        if automatic_close:
            all_fds = range(resource.getrlimit(resource.RLIMIT_NOFILE)[0])
            self.close_fds = set([fd for fd in all_fds if fd not in self.keep_fds])
    
        for fd in self.close_fds:
            try:
                os.close(fd)
                self.closed.add(fd)
                self.logger.info("successfully closed " + str(fd))
            except OSError:
                pass
        
        # All applications must have an open connection to stdin, stdout and stderr
        # even though by design daemons should not actually write to these places.
        # Therefore, if we closed their respective fds, reopen to /dev/null.
        # os.open will open the file and map to the lowest available fd.
        if 0 in self.closed: os.open(devnull, os.O_RDWR)
        if 1 in self.closed: os.open(devnull, os.O_RDWR)
        if 2 in self.closed: os.open(devnull, os.O_RDWR)

        # Set umask to default to safe file permissions when running as a root daemon. 027 is an
        # octal number which we are typing as 0o27 for Python3 compatibility.
        os.umask(0o27)

        # Change to a known directory. If this isn't done, starting a daemon in a subdirectory that
        # needs to be deleted results in "directory busy" errors.
        os.chdir("/")

        # Create a lockfile so that only one instance of this daemon is running at any time.
        lockfile = open(self.pid, "w")
        # Try to get an exclusive lock on the file. This will fail if another process has the file
        # locked.
        fcntl.lockf(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)

        # Record the process id to the lockfile. This is standard practice for daemons.
        lockfile.write("%s" % (os.getpid()))
        lockfile.flush()

        # Set custom action on SIGTERM.
        signal.signal(signal.SIGTERM, self.sigterm)
        atexit.register(self.sigterm)

        self.logger.warn("Starting daemon.")
        self.action()
