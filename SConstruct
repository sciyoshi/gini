# -*- python -*-
#
# GINI Version 2.0
# (C) Copyright 2009, McGill University
#
# Scons compile script for creating GINI installation
#
import os.path
import sys

#import SconsBuilder

try:
  gini_home = os.environ['GINI_HOME']
except KeyError:
  print "ERROR! The GINI_HOME environment variable not set."
  print "Set GINI_HOME and rerun the installation script."
  Exit(1)
Export('gini_home')

#gini_src = os.getcwd()
#Export('gini_src')

env = Environment()
Export('env')

conf = Configure(env)
if not conf.CheckLib('slack'):
  print 'Did not find libslack.a or slack.lib, exiting!'
  Exit(1)
if not conf.CheckLib('readline'):
  print 'Did not find libreadline.so or readline.lib, exiting!'
  Exit(1)
if not conf.CheckLib('pthread'):
  print 'Did not find libpthread.so or pthread.lib, exiting!'
  Exit(1)
env = conf.Finish()

#all_files = Split("""
#AUTHORS
#backend
#ChangeLog
#COPYING
#doc
#frontend
#INSTALL
#README
#SconsBuilderConfig.py
#SconsBuilderDoxygen.py
#SconsBuilder.py
#SConstruct
#THANKS
#TODO""")

SConscript('backend/SConstruct')
SConscript('frontend/SConstruct')

