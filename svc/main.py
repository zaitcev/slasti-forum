#
# Slasti-Forum service.
#
# Copyright (C) 2011 Pete Zaitcev
# See file COPYING for licensing information (expect GPL 2).
#

import base64
import fcntl
import json
import os
import os.path
import select
import socket
import stat
import struct
import sys
from iniparse import ConfigParser
from ConfigParser import NoSectionError, NoOptionError, ParsingError

TAG = "forum-svc"
USOCK = "/tmp/slasti-forum.sock"
PIDFILE = "/var/run/slasti-forum-svc.pid"

connections = {}

class AppError(Exception):
    pass

def Usage():
    print >>sys.stderr, "Usage: "+TAG+" slasti-forum.conf"
    sys.exit(2)

# config()

class ConfigError(Exception):
    pass

# This is what cool people would do, but I don't know how to catch
# improper syntax on this case. Se we just use ConfigParser mode.
# from iniparse import INIConfig
# cfgpr = INIConfig(open(cfgname))

def config_check(cfg):
    if not os.path.isdir(cfg["base"]):
        raise ConfigError("'%s' is not a directory" % cfg["base"])

def config(cfgname, inisect):
    cfg = { }
    cfgpr = ConfigParser()
    try:
        cfgpr.readfp(open(cfgname))
    except IOError, e:
        raise ConfigError(str(e))
    except ParsingError, e:
        # The str(e) may be multiline here, but oh well.
        raise ConfigError("Unable to parse: " + str(e))

    try:
        cfg["base"] = cfgpr.get(inisect, "base")
    except NoSectionError:
        raise ConfigError("Unable to find section '%s'" % inisect)
    except NoOptionError, e:
        raise ConfigError(str(e))

    try:
        cfg["usock"] = cfgpr.get(inisect, "socket")
    except NoOptionError, e:
        cfg["usock"] = USOCK
    try:
        cfg["pidfile"] = cfgpr.get(inisect, "pidfile")
    except NoOptionError, e:
        cfg["pidfile"] = PIDFILE

    #try:
    #    cfg["sleepval"] = float(cfg["sleep"])
    #except ValueError:
    #    raise ConfigError("Invalid sleep value " + cfg["sleep"])

    config_check(cfg)
    return cfg

class Connection:
    def __init__(self, sock):
        self.sock = sock
        self.state = 0

# Packing by hand is mega annoying, but oh well.
def write_pidfile(fname):
    try:
        fd = os.open(fname, os.O_WRONLY|os.O_CREAT, stat.S_IRUSR|stat.S_IWUSR)
    except OSError, e:
        raise AppError(str(e))
    flockb = struct.pack('hhllhh', fcntl.F_WRLCK, 0, 0, 0, 0, 0)
    try:
        fcntl.fcntl(fd, fcntl.F_SETLK, flockb)
    except IOError:
        # EAGAIN is a specific code for already-locked, but whatever.
        raise AppError("Cannot lock %s" % fname)
    if os.write(fd, "%u\n" % os.getpid()) < 1:
        raise AppError("Cannot write %s" % fname)
    try:
        os.fsync(fd)
    except IOError:
        raise AppError("Cannot fsync %s" % fname)
    # not closing the fd, keep the lock
    return fd

def send_challenge(conn):
    # XXX use a random number in the challenge
    chbin = struct.pack("I", 500)
    chstr = base64.b64encode(chbin)
    struc = { "type": 0, "challenge": chstr }
    jmsg = json.dumps(struc)
    msg = struct.pack("!I%ds"%len(jmsg), len(jmsg), jmsg)
    conn.sock.send(msg)

def do(cfg):
    # P3
    print "base  : ", cfg["base"]
    print "socket: ", cfg["usock"]

    pidfd = write_pidfile(cfg["pidfile"])

    poller = select.poll()

    lsock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    lsock.bind(cfg["usock"])
    lsock.listen(5)

    poller.register(lsock.fileno(), select.POLLIN|select.POLLERR)

    while 1:
        # [(fd, ev)]
        events = poller.poll()
        for event in events:
            if event[0] == lsock.fileno():
                (csock, caddr) = lsock.accept()
                conn = Connection(csock)
                connections[csock.fileno()] = conn
                poller.register(csock.fileno(), select.POLLIN|select.POLLERR)
                send_challenge(conn)
            else:
                fd = event[0]
                # P3
                print "event 0x%x fd %d" % (event[1], fd)
                if connections.has_key(fd):
                    conn = connections[fd]
                    if event[1] & select.POLLNVAL:
                        # P3
                        print "event: POLLNVAL"
                        poller.unregister(fd)
                        connections[fd] = None
                    elif event[1] & select.POLLHUP:
                        # P3
                        print "event: POLLHUP"
                        poller.unregister(fd)
                        connections[fd] = None
                    elif event[1] & select.POLLERR:
                        # P3
                        print "event: POLLERR"
                        poller.unregister(fd)
                        connections[fd] = None
                    elif event[1] & select.POLLIN:
                        # P3
                        print "event: POLLIN"
                        if conn.state == 0:
                            print "connection found, no session"
                        else:
                            print "connection found, has a session"
                    else:
                        # P3
                        print "event: UNKNOWN"
                        poller.unregister(fd)
                        connections[fd] = None
                else:
                    # P3
                    print "UNKNOWN connection"

def main(args):
    argc = len(args)
    if argc == 1:
        cfgname = args[0]
    else:
        Usage()

    try:
        cfg = config(cfgname, "svc")
    except ConfigError, e:   # This is our exception. Other types traceback.
        print >>sys.stderr, "Error in config file '" + cfgname + "':", e
        sys.exit(1)

    try:
        do(cfg)
    except AppError, e:
        print >>sys.stderr, TAG+":", e
        sys.exit(1)
    except KeyboardInterrupt:
        # The stock exit code is also 1 in case of signal, so we are not
        # making it any worse. Just stubbing the traceback.
        sys.exit(1)

# http://utcc.utoronto.ca/~cks/space/blog/python/ImportableMain
if __name__ == "__main__":
    main(sys.argv[1:])
