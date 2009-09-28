#!/usr/bin/python

# Written by Reehan Shaikh
# Last update: April 11, 2006
# Adapted from program.py

from optparse import OptionParser
import os

import xml_processor

class Start:
    "Class to define the gloader program structure"
    progName = ""       # name of the program
    setupFile = ""      # file that contains the setup

    optParser = None    # the parser to parse the cmd line options
    options = None      # the cmd line option storage
    distOpt = False   	# to check whether the distribute option is used
    undistOpt = False  	# to check whether the undistribute option is used
    ipOpt = False	# to check where the ipFile is given on the command line

    giniNW = None       # the gini network framework

    def __init__(self, pName, fileName):
        "Initialize the Program class"
        self.progName = pName
        self.setupFile = fileName
        self.optParser = OptionParser(usage=self.usage())
        self.optParser.add_option("-x", "--distribute", \
                                  action="callback",\
                                  callback=self.distCallBack,\
                                  dest="xmlFile",\
                                  help="Distribute a GINI instance")
        self.optParser.add_option("-y", "--undistribute", \
                                  action="callback",\
                                  callback=self.undistCallBack,\
                                  dest="xmlFile",\
                                  help="Undistribute a GINI instance")
        self.optParser.add_option("-i", "--ipFile", \
                                  action="callback",\
                                  callback=self.ipCallBack,\
                                  dest="ipSpecs",\
                                  help="File that contains the IPs you want to distribute to")
        self.optParser.add_option("-s", "--switch-dir", \
                                  dest="switchDir",\
                                  default=".",\
                                  help="Specify the switch configuration directory")
        self.optParser.add_option("-r", "--router-dir", \
                                  dest="routerDir",\
                                  default=".",\
                                  help="Specify the router configuration directory")
        self.optParser.add_option("-u", "--uml-dir", \
                                  dest="umlDir",\
                                  default="",\
                                  help="Specify the UML configuration directory")
        self.optParser.add_option("-b", "--bin-dir", \
                                  dest="binDir",\
                                  default="",\
                                  help="Specify the directory of the GINI binaries")
        self.optParser.add_option("-k", "--keep-old", \
                                  dest="keepOld",\
                                  action="store_true",\
                                  default=False,\
                                  help="Specify not to destroy existing GINI instances")

    def usage(self):
        "creates the usage message"
        usageString = self.progName + "\n"
        usageString += " (-x [gdist-xml-file] | -y [gdist-xml-file])\n"
        usageString += " (-i [gdist-ip-file])\n"
        usageString += " [-s swich-dir]\n"
        usageString += " [-r router-dir]\n"
        usageString += " [-u uml-dir]\n"
        usageString += " [-b bin-dir]\n"
        usageString += " [-k]"
        return usageString

    def distCallBack(self, option, opt_str, value, parser):
        "Handling option -x"
        value = ""
        rargs = parser.rargs
        if (len(rargs) > 0):
            currArg = rargs[0]
            if (currArg[:1] != "-"):
                value = currArg
                del rargs[0]
        self.distOpt = True
        setattr(parser.values, option.dest, value)
        
    def undistCallBack(self, option, opt_str, value, parser):
        "Handling option -y"
        value = ""
        rargs = parser.rargs
        if (len(rargs) > 0):
            currArg = rargs[0]
            if (currArg[:1] != "-"):
                value = currArg
                del rargs[0]
        self.undistOpt = True
        setattr(parser.values, option.dest, value)

    def ipCallBack(self, option, opt_str, value, parser):
        "Handling option -i"
        value = ""
        rargs = parser.rargs
        if (len(rargs) > 0):
            currArg = rargs[0]
            if (currArg[:1] != "-"):
                value = currArg
                del rargs[0]
        self.ipOpt = True
        setattr(parser.values, option.dest, value)
        
    def processOptions(self,args):
        "Processing options and checking the provided XML file (if any)"
        # parse the command line arguments and extract options
        (self.options, args) = self.optParser.parse_args(args)
        # check the extract options and generate necessary
        # error messages
        if (self.distOpt and self.undistOpt):
            print "Use either -x or -y, not both"
            print self.usage()
            return False
        if ((not self.distOpt) and (not self.undistOpt)):
            print "At least -x or -y option should be given"
            print self.usage()
            return False
        # if no XML file is given read from the gini setup file
        if (not self.options.xmlFile):
            if (os.access(self.setupFile, os.R_OK)):
                setupFileHandle = open(self.setupFile)
                lines = setupFileHandle.readlines()
                self.options.xmlFile = lines[0].strip()
                self.options.switchDir = lines[1].strip()
                self.options.routerDir = lines[2].strip()
                self.options.umlDir = lines[3].strip()
                self.options.binDir = lines[4].strip()
                setupFileHandle.close()
            else:
                print "No XML file specified and no setup file in the current directory"
                return False
        # check the validity of the XML file
        if (not os.access(self.options.xmlFile, os.R_OK)):
            print "Cannot read file \"" + self.options.xmlFile + "\""
            return False
        # if everything is fine, start XML processing
        if (self.options.xmlFile != ""):
            myXMLProcess = xml_processor.XMLProcessor(self.options.xmlFile)
            if (not myXMLProcess.checkSemantics()):
                return False
        # get the GINI network setup from the XML processor
        self.giniNW = myXMLProcess.giniNW
        # if no ipSpecs file is given read from the gini setup file
        if (not self.options.ipSpecs):
            if (os.access(self.setupFile, os.R_OK)):
                setupFileHandle = open(self.setupFile)
                lines = setupFileHandle.readlines()
                self.options.ipSpecs = lines[5].strip()
                setupFileHandle.close()
            else:
                print "No IP file specified and no setup file in the current directory"
                return False
        # check the validity of the IP file
        if (not os.access(self.options.ipSpecs, os.R_OK)):
            print "Cannot read file \"" + self.options.ipSpecs + "\""
            return False
        return True
