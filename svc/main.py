#
# Slasti-Forum service.
#
# Copyright (C) 2011 Pete Zaitcev
# See file COPYING for licensing information (expect GPL 2).
#

import sys
from iniparse import ConfigParser
from ConfigParser import NoSectionError, NoOptionError

TAG = "forum-svc"

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

def config(cfgname, inisect):
    cfg = { }
    cfgpr = ConfigParser()
    try:
        cfgpr.read(cfgname)
        cfg["base"] = cfgpr.get(inisect, "base")
    except NoSectionError:
        # Unfortunately if the file does not exist, we end here.
        raise ConfigError("Unable to open or find section " + inisect)
    except NoOptionError, e:
        raise ConfigError(str(e))

    #try:
    #    cfg["sleepval"] = float(cfg["sleep"])
    #except ValueError:
    #    raise ConfigError("Invalid sleep value " + cfg["sleep"])

    return cfg

def do(cfg):
    print "base: ", cfg["base"]

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

# http://utcc.utoronto.ca/~cks/space/blog/python/ImportableMain
if __name__ == "__main__":
    main(sys.argv[1:])
