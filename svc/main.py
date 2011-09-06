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
        cfg["admin"] = cfgpr.get(inisect, "admin")
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

# XXX Find a way to share this with cli/.
# Pull a bytearray of size bytes out of the list of strings, copy it out.
def skb_pull_copy(mbufs, size):
    v = bytearray(size)
    mx = 0
    x = 0
    done = 0
    while done < size:
       mbuf = mbufs[mx]
       steplen = size - done
       if len(mbuf) < steplen:
           steplen = len(mbuf)
       v[done:done+steplen] = mbuf[x:x+steplen]
       done += steplen
       x += steplen
       if x >= len(mbuf):
           x = 0
           mx += 1
    return v

# Pull a bytearray from mbufs and (in the future XXX) remove from mbufs,
# in order to permit repeated pull calls when the message length is known.
# XXX For now, we just do nothing... so it's the same deal as skb_pull_copy.
def skb_pull(mbufs, size):
    return skb_pull_copy(mbufs, size)

class Connection:
    def __init__(self, sock):
        self.sock = sock
        self.state = 0
        self.mbufs = []
        self.rcvd = 0
    def mark_login(self):
        self.state = 1
    def mark_dead(self):
        self.state = 2

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

def send_ack(conn):
    struc = { "type": 2 }
    jmsg = json.dumps(struc)
    msg = struct.pack("!I%ds"%len(jmsg), len(jmsg), jmsg)
    conn.sock.send(msg)

def send_nak(conn, msg):
    struc = { "type": 3, "error": msg }
    jmsg = json.dumps(struc)
    msg = struct.pack("!I%ds"%len(jmsg), len(jmsg), jmsg)
    conn.sock.send(msg)

def recv_msg(conn, msg, cfg):
    # P3
    print "svc-rcvd[%d]: "%len(msg), msg
    struc = json.loads(msg)
    print "type:", struc['type']

    if struc['type'] == 1:
        # XXX verify password
        conn.mark_login()
        send_ack(conn)
    elif struc['type'] == 4:
        if struc['name'][0:1] != "/":
            send_nak(conn, "no leading slash")
            return
        try:
            os.mkdir(cfg['base']+struc['name'])
        except OSError, e:
            send_nak(conn, "unable to create")
        except:
            # TypeError or KeyError if wrong structure
            send_nak(conn, "exception on create")
        send_ack(conn)
    elif struc['type'] == 5:
        conn.mark_dead()
    else:
        send_nak(conn, "unknown msg type %s" % str(struc['type']))

def recv_event(conn, cfg):
    # Always receive the socket data, or else the poll would loop.
    mbuf = conn.sock.recv(4096)
    if mbuf == None:
        # Curious - does it happen? XXX
        print >>sys.stderr, "Received None"
        sys.exit(1)
    conn.mbufs.append(mbuf)
    conn.rcvd += len(mbuf)

    if conn.rcvd < 4:
        return
    hdr = skb_pull_copy(conn.mbufs, 4)

    # This produces a string if hdr is an str. Works great for bytearray.
    length = hdr[1]*256*256 + hdr[2]*256 + hdr[3]
    # This works if hdr is a string, fails for bytearray with struct.error.
    # length = struct.unpack("!I", hdr)[0] & 0xFFFFFF

    if conn.rcvd < 4 + length:
        return
    buf = skb_pull(conn.mbufs, 4 + length)

    recv_msg(conn, str(buf[4:]), cfg)

    # XXX Fix this once skb_pull works as intended.
    conn.mbufs = []
    conn.rcvd = 0

    return

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
                if connections.has_key(fd):
                    conn = connections[fd]
                    if event[1] & select.POLLNVAL:
                        poller.unregister(fd)
                        connections[fd] = None
                    elif event[1] & select.POLLHUP:
                        poller.unregister(fd)
                        connections[fd] = None
                    elif event[1] & select.POLLERR:
                        poller.unregister(fd)
                        connections[fd] = None
                    elif event[1] & select.POLLIN:
                        # P3
                        if conn.state == 0:
                            print "connection found, no session"
                        else:
                            print "connection found, has a session"
                        recv_event(conn, cfg)
                        if conn.state == 2:
                            poller.unregister(fd)
                            connections[fd] = None
                    else:
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
