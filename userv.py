# NOTE: This code has been inspired and influenced by many pieces of external
# code. To give credit where credit is due, they are listed here.
# * https://pagure.io/python-daemon/blob/master/f/daemon/daemon.py
# * https://github.com/eestrada/pygdrived/blob/master/src/gdrive/daemon.py
from __future__ import division, absolute_import, print_function

import io
import os
import sys
import time
import errno
import atexit
import signal
import socket
import logging
import getpass
import tempfile
import resource


class ServiceContext(object):

    """Sets up and tears down a daemon service as a context manager.

    Within the context, a long running process should be called. If called
    directly thru the `start` method, a long running process can instead be
    specified in the `run` method of a subclass. This makes it easier to
    simplify coding start/stop/restart/status control flow.
    """

    def __init__(self, files_preserve=None, chroot_directory=None,
                 working_directory='/', umask=0, pidfile=None,
                 detach_process=True, signal_map=None, uid=None,
                 gid=None, prevent_core=True, stdin=None, stdout=None,
                 stderr=None, logger_name=None, auto_run=True):
        """Initilize a ServiceContext instance.

        An explicit "pidfile" should be specified, otherwise unrelated
        ServiceContext instances for different daemons may try to delete
        eachother. However, all other keyword arguments have usable default
        values.
        """
        self.files_preserve = files_preserve
        self.chroot_directory = chroot_directory
        self.working_directory = working_directory
        self.umask = umask

        if pidfile is None:
            pidfile = getpass.getuser() + '_generic_daemon.pid'
            pidfile = os.path.join(tempfile.gettempdir(), pidfile)
        self.pidfile = pidfile

        self.detach_process = detach_process
        self.signal_map = (self.make_default_signal_map()
                           if signal_map is None else signal_map)
        self.uid = os.getuid() if uid is None else uid
        self.gid = os.getgid() if gid is None else gid
        self.prevent_core = prevent_core

        self.stdin = self.stdout = self.stderr = None
        for name, fp, mode in (('stdin', stdin, 'rt'),
                               ('stdout', stdout, 'wt'),
                               ('stderr', stderr, 'wt')):
            if fp is None:
                setattr(self, name, io.open(os.devnull, mode))
            elif hasattr(fp, 'fileno'):
                setattr(self, name, fp)
            else:
                setattr(self, name, io.open(fp, mode))

        self.log = logging.getLogger(logger_name)
        self.auto_run = auto_run

        self.is_open = False

    def __enter__(self):
        _auto_run = self.auto_run
        self.auto_run = False
        try:
            self.start()
        finally:
            self.auto_run = _auto_run
        return self

    def __exit__(self, *args):
        self.stop()
        return False

    @classmethod
    def is_process_started_by_init(cls):
        """Determine whether the current process is started by `init`.

        :return: ``True`` if the parent process is `init`; otherwise
            ``False``.

        `init` process has the process ID of 1.
        """
        INIT_PID = 1
        if os.getppid() == INIT_PID:
            return True
        else:
            return False

    @classmethod
    def is_socket(cls, fd):
        """Determine whether the file descriptor is a socket.

        :param fd: The file descriptor to interrogate.
        :return: ``True`` iff the file descriptor is a socket; otherwise
            ``False``.

        Query the socket type of `fd`. If there is no error, the file is a
        socket.
        """
        file_socket = socket.fromfd(fd, socket.AF_INET, socket.SOCK_RAW)
        try:
            file_socket.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        except socket.error as exc:
            exc_errno = exc.args[0]
            if exc_errno == errno.ENOTSOCK:
                # Socket operation on non-socket.
                return False
            else:
                # Some other socket error.
                return True
        else:
            # No error getting socket type.
            return True

    @classmethod
    def is_process_started_by_superserver(cls):
        """Determine whether the current process is started by the superserver.

        :return: ``True`` if this process was started by the internet
            superserver; otherwise ``False``.

        The internet superserver creates a network socket, and
        attaches it to the standard streams of the child process. If
        that is the case for this process, return ``True``, otherwise
        ``False``.
        """
        stdin_fd = sys.__stdin__.fileno()
        if self.is_socket(stdin_fd):
            return True
        else:
            return False

    def _fork(self, errmsg="fork failed"):
        try:
            pid = os.fork()
        except OSError as e:
            fmt = errmsg + ": %d (%s)"
            self.log.error(fmt, e.errno, e.strerror)
            raise
        else:
            if pid > 0:  # exit from first parent without running cleanup
                os._exit(0)


    def detach(self):
        """Detach process into its own process group.

        Also, disassociate process from any controlling terminal.

        We do this using the UNIX double-fork magic. See Stevens' "Advanced
        Programming in the UNIX Environment" for details (ISBN 0201563177). The
        historical URL that everyone points to is
        "http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16", however that
        now seems to be a dead link. We should replace it with one that
        actually works.
        """
        if self.detach_process is None:
            # NOTE: `None` value indicates "Let the Unix Service class
            # determine if we need to detach."

            if self.is_process_started_by_init() or self.is_process_started_by_superserver():
                self.log.info("Process started by init or inetd. No need to detach.")
                return
        elif not self.detach_process:
            self.log.info("Service set to not detach.")
            return

        # fork, decouple from parent environment, fork again
        self._fork(errmsg="fork #1 failed")
        os.setsid()
        self._fork(errmsg="fork #2 failed")

    def set_environment(self):
        """Set up execution environment.

        Set the chroot directory (if it is not `None`), the working directory, the UID,
        the GID, and the umask.
        """
        if self.chroot_directory is not None:
            os.chroot(self.chroot_directory)
        os.setuid(self.uid)
        os.setgid(self.gid)
        os.chdir(self.working_directory)
        os.umask(self.umask)

    def close_fds(self):
        """Close file descriptors.

        Excludes self.stdin, self.stdout, self.stderr and any files specified
        in self.files_preserve. Files may be file objects with a working
        `fileno` method or integers representing file descriptors.
        """
        # flush then redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()

        for self_fp, sys_fp in ((self.stdin, sys.stdin),
                                (self.stdout, sys.stdout),
                                (self.stderr, sys.stderr)):
           os.dup2(self_fp.fileno(), sys_fp.fileno())

        # close open file descriptors
        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        maxfd = maxfd if maxfd != resource.RLIM_INFINITY else 1024

        to_ignore = [self.stdin, self.stdout, self.stderr]
        to_ignore.extend(self.files_preserve or [])
        to_ignore = set(f if isinstance(f, int) else f.fileno() for f in to_ignore)

        fdset = set(range(0, maxfd)) - to_ignore
        fdslist = sorted(fdset)

        for fd in fdslist:
            try:
                os.close(fd)
            except OSError:
                pass

    @classmethod
    def make_default_signal_map(cls):
        """Make the default signal map for this system.

        :return: A mapping from signal number to handler object.

        The signals available differ by system. The map will not contain
        any signals not defined on the running system.
        """
        name_map = {
                'SIGTSTP': signal.SIG_IGN,
                'SIGTTIN': signal.SIG_IGN,
                'SIGTTOU': signal.SIG_IGN,
                'SIGTERM': (lambda sig, frame: sys.exit()),
                }
        signal_map = dict(
                (getattr(signal, name), target)
                for (name, target) in name_map.items()
                if hasattr(signal, name))
        return signal_map

    def set_signals(self):
        """Set handlers for various signals.

        :return: ``None``.

        See the `signal` module for details on signal numbers and signal
        handlers.
        """
        for (sig, handler) in self.signal_map.items():
            signal.signal(sig, handler)

    def write_pidfile(self):
        """Write pid to pidfile on disk."""
        pid = str(os.getpid())
        with io.open(self.pidfile, 'wt') as pidfile:
            pidfile.write("%s\n" % pid)

    def getfilepid(self):
        """Get pid from pidfile on disk."""
        with io.open(self.pidfile, 'rt') as pf:
            _line1 = pf.readline()
            _item1 = _line1.split(maxsplit=1)[0]
            return int(_item1.strip())

    def remove_pidfile(self):
        """Remove pidfile from disk."""
        try:
            os.remove(self.pidfile)
        except OSError:
            # NOTE: It's Ok if the file is already gone.
            pass

    def prevent_core_dump(self):
        core_resource = resource.RLIMIT_CORE
        try:
            # Ensure the resource limit exists on this platform, by requesting
            # its current value.
            resource.getrlimit(core_resource)
        except ValueError as exc:
            msg = "System does not support RLIMIT_CORE resource limit (%s)"
            self.log.error(msg, exc)
            raise Exception(msg % exc) from exc

        # Set hard and soft limits to zero, i.e. no core dump at all.
        core_limit = (0, 0)
        resource.setrlimit(core_resource, core_limit)

    def status(self):
        """Check status of service daemon.

        Return a tuple of (status, message). Status will be `True`, `False` or
        `None` depending on whether the daemon is running (`True`), not running
        (`False`), or in an unspecified error state (`None`). The message will
        be a human readable status message.
        """
        try:
            pid = self.getfilepid()
        except IOError:
            message = 'Pidfile "%s" does not exist. Daemon likely not running.'
            return (False, message % self.pidfile)

        try:
            os.kill(pid, 0)  # NOTE: Check if process with PID is running
            return (True, 'Pidfile "%s" points to PID %d. A process with '
                    'this PID is running, thus the service daemon is likely '
                    'running.' % (self.pidfile, pid))
        except OSError as e:
            if e.errno == errno.EPERM:
                return (True, 'Pidfile "%s" points to PID %d, which is '
                        'currently running. However, you do not have '
                        'permission to access the process.'
                        % (self.pidfile, pid))
            elif e.errno == errno.ESRCH:
                return (False, 'Pidfile "%s" points to PID %d. This '
                        'process does not exist. Please delete pidfile.'
                        % (self.pidfile, pid))
            else:
                rval = (None, 'The pidfile "%s" points to PID %d. We '
                        'could not access the PID. We do not know why.'
                        % (self.pidfile, pid))
                self.log.exception(rval[1])
                return rval

    def start(self):
        """Daemonize current process."""
        if self.is_open:
            return
        elif self.status()[0]:
            raise RuntimeError(self.status()[1])

        self.log.info('Starting daemonization.')
        self.detach()
        if self.prevent_core:
            self.prevent_core_dump()
        self.set_signals()
        self.close_fds()
        self.set_environment()
        self.write_pidfile()
        self.is_open = True

        atexit.register(self.stop)
        self.log.info('Running daemonized.')

        if self.auto_run:
            try:
                self.run_main()
            except BaseException as e:
                self.log.debug('Does this ever get hit?', exc_info=True)
                raise e

    def stop_self(self):
        """Clean up after this process."""
        self.remove_pidfile()
        return True

    def stop_other(self, pid):
        """Kill a running copy of this daemon that is not this process."""
        # Try killing the daemon process
        try:
            while True:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError as e:
            # NOTE: Error number for "No such process"
            if e.errno == errno.ESRCH:
                self.remove_pidfile()
                return True
            else:
                self.log.warning(str(e.strerror))
                return False

    def stop(self):
        """Stop and clean up daemon.

        Normally run at exit using the `atexit` library, or is run as part of
        the `__exit__` method from a `with` context.
        """
        if self.is_open or self.status()[0]:
            self.is_open = False
        elif not self.is_open:
            self.log.info('Daemon is already stopped. Nothing to do.')
            return False

        self.log.info('Stopping daemon.')
        try:
            pid = self.getfilepid()
        except IOError:
            message = 'pidfile "%s" does not exist. Daemon likely not running?'
            self.log.warning(message, self.pidfile)
            return False  # NOTE: not an error in a restart
        return self.stop_self() if pid == os.getpid() else self.stop_other(pid)

    def restart(self):
        """Convenience method to stop and then immediatly start the daemon."""
        self.stop()
        self.start()

    def run_main(self):
        """Run main daemon code.

        Meant to be overridden in a subclass. However, this is optional; if the
        class is run as a context manager, it is completely ignored. It is only
        run when `start` is called directly AND the `auto_run` flag is set to
        True (the default) on the object at instantiation. Code in this clause
        should not call other daemon related code in this class (such as
        `start` or `stop`).

        This method can also be run directly to run code undaemonized. That is,
        to run it in the foreground.
        """
        self.log.info('Running main code.')
        raise NotImplementedError

