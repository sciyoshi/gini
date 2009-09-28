""" Various global variables """
import os

PROG_NAME = "gBuilder"
PROG_VERSION  = "2.0.0"

environ = {"os":"Windows",
           "path":os.environ["GINI_HOME"]+"/",
           "remotepath":"./",
           "images":os.environ["GINI_HOME"]+"/share/gbuilder/images/",
           "config":os.environ["GINI_HOME"]+"/etc/",
           "sav":os.environ["GINI_HOME"]+"/sav/",
           "tmp":os.environ["GINI_HOME"]+"/tmp/",
           "doc":os.environ["GINI_HOME"]+"/doc/"}

options = {"names":True,
           "systray":False,
           "elasticMode":False, "keepElasticMode":False,
           "smoothing":True, "glowingLights":True, "style":"Plastique",
           "grid":True, "gridColor":"(240,240,240)",
           "background":environ["images"] + "background.jpg",
           "windowTheme":environ["images"] + "background2.jpg",
           "baseTheme":environ["images"] + "background3.jpg",
           "autorouting":True, "autogen":True, "autocompile":True,
           "graphing":True, "username":"",
           "server":"localhost", "session":"GINI", "autoconnect":True,
           "localPort":"10001", "remotePort":"10000",
           "restore":True}

mainWidgets = {"app":None,
               "main":None,
               "canvas":None,
               "tab":None,
               "popup":None,
               "log":None,
               "tm":None,
               "properties":None,
               "interfaces":None,
               "routes":None,
               "drop":None,
               "client":None}

defaultOptions = {"palette":None}
