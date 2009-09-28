#!/usr/bin/python

import sys, os

# Check python version number
if sys.version_info[:2] != (2, 5) and sys.version_info[:2] != (2, 6):
    raw_input("Error: Use Python version 2.5 or 2.6")
    sys.exit(1)

# Check if PyQt4 is installed
try:
    from PyQt4 import QtCore, QtGui
except ImportError, err:
    print "ImportError: ", err
    raw_input("PyQt4 must be installed.  Press Enter to quit.")
    sys.exit(1)
   
# Check if we have GINI_HOME set
if not os.environ.has_key("GINI_HOME"):
    raw_input("Environment variable GINI_HOME not set, please set it before running gbuilder!")
    sys.exit(1)
        
import UI.MainWindow
import Core.globals

def demo(canvas):
    pass

if __name__ == "__main__":
    
    app = QtGui.QApplication(sys.argv)

    QtCore.qsrand(QtCore.QTime(0,0,0).secsTo(QtCore.QTime.currentTime()))
    mainWindow = UI.MainWindow.MainWindow(app)
    #demo(mainWindow.centralWidget())
    
    mainWindow.setWindowTitle(QtCore.QObject.tr(mainWindow, 
        "%s %s" % (Core.globals.PROG_NAME, Core.globals.PROG_VERSION)))
    mainWindow.setWindowIcon(QtGui.QIcon(os.environ["GINI_HOME"] + "/share/gbuilder/images/giniLogo.png"))
    mainWindow.setMinimumSize(640, 480)
    mainWindow.resize(800, 600)

    sys.exit(app.exec_())
