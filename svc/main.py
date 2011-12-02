#
# Slasti-Forum service.
#
# Copyright (C) 2011 Pete Zaitcev
# See file COPYING for licensing information (expect GPL 2).
#

import base64
import fcntl
import forumlib
import hashlib
import json
import os
import os.path
import select
import socket
import stat
import string
import struct
import sys
import types
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

class Connection:
    def __init__(self, sock):
        self.challenge = None
        self.sock = sock
        self.state = 0
        self.user = None
        self.mbufs = []
        self.rcvd = 0
    def mark_login(self, username):
        self.state = 1
        self.user = username
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

def send_msg(sock, struc):
    jmsg = json.dumps(struc)
    jlen = len(jmsg)
    if jlen >= 0x1000000:
        raise AppError("message too long")
    msg = struct.pack("!I%ds"%jlen, jlen, jmsg)
    sock.send(msg)

def send_ack(conn):
    send_msg(conn.sock, { "type": 2 })

def send_nak(conn, msg):
    send_msg(conn.sock, { "type": 3, "error": msg })

def login(cfg, conn, struc):
    try:
        username = struc['user']
        hashtype = struc['hash']
        hashstr = struc['login']
    except:
        # TypeError or KeyError if wrong structure
        send_nak(conn, "exception")
        return

    if hashtype != 'sha256':
        send_nak(conn, "unknown hash")
        return
    if (not (type(username) is types.UnicodeType or
             type(username) is types.StringType)) or len(username) == 0:
        send_nak(conn, "bad user")
        return
    if not (type(hashstr) is types.UnicodeType or
            type(hashstr) is types.StringType):
        send_nak(conn, "bad hash")
        return

    # XXX Add more users.
    if username != "admin":
        send_nak(conn, "unknown user")
        return
    password = cfg['admin']

    loghash = hashlib.sha256()
    loghash.update(conn.challenge+password)
    logstr = loghash.hexdigest()
    if logstr != hashstr:
        send_nak(conn, "login incorrect")
        return

    conn.mark_login(username)
    send_ack(conn)

def new_section(cfg, conn, struc):
    try:
        secname = struc['name']
        sectitle = struc['title']
        secdesc = struc['desc']
    except:
        # TypeError or KeyError if wrong structure
        send_nak(conn, "exception")
        return

    if secname[0:1] != "/":
        send_nak(conn, "no leading slash")
        return
    try:
        os.mkdir(cfg['base']+secname+'.dir')
    except OSError, e:
        send_nak(conn, "unable to create")
        return
    except:
        # TypeError or KeyError if wrong structure
        send_nak(conn, "exception on create")
        return

    try:
        f = open(cfg['base']+secname+'.sum', "w+")
    except IOError, e:
        send_nak(conn, "exception on summary")
        return

    f.write(sectitle)
    f.write("\n")
    f.write(secdesc)
    f.write("\n")

    f.close()

    send_ack(conn)

def new_thread(cfg, conn, struc):
    try:
        sect = struc['section']
        if sect[0:1] != "/":
            send_nak(conn, "no leading slash")
            return
    except:
        # TypeError or KeyError if wrong structure
        send_nak(conn, "exception")
        return
    if not os.path.isdir(cfg['base']+sect+'.dir'):
        send_nak(conn, "bad section")
        return

    try:
        # XXX the 'name' needs to be validated against slash and '..'
        os.mkdir(cfg['base']+sect+'.dir/'+struc['name'])
    except OSError, e:
        send_nak(conn, "unable to create")
        return
    except:
        # TypeError or KeyError if wrong structure
        send_nak(conn, "exception on create")
        return

    try:
        f = open(cfg['base']+sect+'.dir/'+struc['name']+'.sum', "w+")
    except IOError, e:
        send_nak(conn, "exception on summary")
        return

    f.write(struc['subject'])
    f.write("\n")

    f.close()

    send_ack(conn)

def new_message(cfg, conn, struc):
    try:
        sect = struc['section']
        if sect[0:1] != "/":
            send_nak(conn, "no leading slash")
            return
        thrd = struc['thread']
    except:
        # TypeError or KeyError if wrong structure
        send_nak(conn, "exception")
        return
    if not os.path.isdir(cfg['base']+sect+'.dir/'+thrd):
        send_nak(conn, "bad thread path")
        return

    try:
        username = struc['user']
    except:
        username = conn.user

    try:
        f = open(cfg['base']+sect+'.dir/'+thrd+'/'+struc['name'], "w+")
    except IOError, e:
        send_nak(conn, "exception on summary")
        return

    # XXX Maybe write as JSON on the back-end too?
    f.write("%s\n" % username)
    f.write("\n")
    f.write(struc['body'])
    # f.write("\n")

    f.close()

    send_ack(conn)

def load_section(cfg, sect):
    sdic = {}

    sdic['name'] = '/'+sect

    try:
        f = open(cfg['base']+'/'+sect+'.sum', "r")
    except IOError:
        f = None
    if f != None:
        # XXX This cannot be the most pythoic way to drop trailing newline
        s = f.readline()
        if s[-1] == '\n':
            s = s[:-1]
        sdic['title'] = s
        s = f.readline()
        if s[-1] == '\n':
            s = s[:-1]
        sdic['desc'] = s
        f.close()

    return sdic

def list_sections(cfg, conn):
    toplist = os.listdir(cfg['base'])
    toplist.sort()
    # toplist.reverse()

    vec = []
    for name in toplist:
        fname = name.encode('ascii')       # XXX try/except this one day
        p = string.split(fname, '.')
        if p[-1] == 'dir':
            vec.append(load_section(cfg, fname[:-4]))

    struc = {}
    struc['type'] = 9
    struc['v'] = vec
    send_msg(conn.sock, struc)

def recv_msg(cfg, conn, msg):
    # P3
    print "svc-rcvd[%d]: "%len(msg), msg
    struc = json.loads(msg)

    # Type 1 is the only message permitted when conn.state is not 1 (logged-in).
    if struc['type'] == 1:
        login(cfg, conn, struc)
        return
    if conn.state != 1:
        send_nak(conn, "bad login state %d" % conn.state)
        return

    if struc['type'] == 4:
        new_section(cfg, conn, struc)
    elif struc['type'] == 5:
        conn.mark_dead()
    elif struc['type'] == 6:
        new_message(cfg, conn, struc)
    elif struc['type'] == 7:
        new_thread(cfg, conn, struc)
    elif struc['type'] == 8:
        list_sections(cfg, conn)
    else:
        send_nak(conn, "unknown msg type %s" % str(struc['type']))

def recv_event(cfg, conn):
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
    hdr = forumlib.skb_pull_copy(conn.mbufs, 4)

    # This produces a string if hdr is an str. Works great for bytearray.
    length = hdr[1]*256*256 + hdr[2]*256 + hdr[3]
    # This works if hdr is a string, fails for bytearray with struct.error.
    # length = struct.unpack("!I", hdr)[0] & 0xFFFFFF

    if conn.rcvd < 4 + length:
        return
    buf = forumlib.skb_pull(conn.mbufs, 4 + length)

    recv_msg(cfg, conn, str(buf[4:]))

    # XXX Fix this once skb_pull works as intended.
    conn.mbufs = []
    conn.rcvd = 0

    return

def send_challenge(conn):
    conn.challenge = os.urandom(4)
    chstr = base64.b64encode(conn.challenge)
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
                        recv_event(cfg, conn)
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
