#!/usr/bin/python

# Written by Reehan Shaikh
# Last update: April 11, 2006
# Adapted from gloader.py

# Revised by Daniel Ng

import sys, os, signal, time

from starter import Start
#import batch_ipcrm
import Pyro.core

debug_mode = 0
debug_uswitch = 0

# set the program names
VS_PROG = "uswitch"
VM_PROG = "glinux"
GR_PROG = "grouter"
MCONSOLE_PROG = "uml_mconsole"
SOCKET_NAME = "gini_socket"
VS_PROG_BIN = VS_PROG
VM_PROG_BIN = VM_PROG
GR_PROG_BIN = GR_PROG
MCONSOLE_PROG_BIN = MCONSOLE_PROG
SRC_FILENAME = "%s/gini_dist" % os.environ["GINI_HOME"] # setup file name
UML_WAIT_DELAY = 1.5 # wait delay between checking alive UML
GROUTER_WAIT = 0.5 # wait delay between starting routers
GINI_TMP_FILE = "gini_tmp_file" # tmp file used when checking alive UML
LOG_FILE = "gdist_log" # log file for gloader messages
SCREEN_LOG = False # telling to enable/disable screenlog file
SSHOPTS = " -o StrictHostKeyChecking=false "

# set this flag to True if running without gbuilder
independent = False
if not independent:
    uriIn = open("%s/tmp/pyro_uris" % os.environ["GINI_HOME"], "r")
    uri = uriIn.readline().strip()
    uri2 = uriIn.readline().strip()
    uriIn.close() 

# start the network
def distGINI(myGINI, options, ips):
    "starting the GINI network components"
    # the starting order is important here
    # first switches, then routers, and at last UMLs.
    print "\nStarting GINI switches..."
    success = createVS(myGINI, options, ips)
    return success

# create a switch for every UML and router interface so that these
# components can interact with eaech other over sockets
def createVS(myGINI, options, ips):
    "create the switch config file and start the switch for UML and router interfaces"
    success = True

    if not independent:
        sys.stdout = open("/dev/null", "w")
        tm = Pyro.core.getProxyForURI(uri2)
        sys.stdout = sys.__stdout__

    # create the real switch devices
    for i in range(0, len(ips[5]), 2):
        print "Starting real Switch on machine %s...\t" % (ips[5][i])

        # find the j that corresponds to the machine the switch is running on
        for j in range(0, len(ips[0]), 2):
            if (ips[0][j] == ips[5][i]):
                break

        remotes = []
        unique_port = 0
        for h in range(0, len(ips[3]), 4):        
            if (ips[3][h] == ips[5][i+1].name):
                
                if ips[3][h+1]:
                    if not remotes.count(ips[3][h+1]):
                        remotes.append(ips[3][h+1])
                # take the first unique port to share among destinations
                if not unique_port and ips[3][h+3]:
                    unique_port = ips[3][h+3]    
                    
        # create a SWITCH directory on remote machine, under the given specified directory from the IP file
        subSwitchDir = "%s/GINI/%s" % (ips[0][j + 1], ips[5][i+1].name)
        os.system("ssh" + SSHOPTS + ips[5][i] + " rm -rf " + subSwitchDir)
        time.sleep(GROUTER_WAIT)
        os.system("ssh" + SSHOPTS + ips[5][i] + " mkdir " + subSwitchDir)
        
        # create script files to run on remote machines
        scrpt = open("switch.sh", 'w')
        if unique_port:
            remotestring = ""
            for remoteIP in remotes:
                remotestring += "-r %s " % remoteIP.split("@")[-1]
            command = "cd %s/\n%s -s %s.ctl -l uswitch.log -p uswitch.pid -u %d %s" % (subSwitchDir, VS_PROG, SOCKET_NAME, unique_port, remotestring)
        else:
            command = "cd %s/\n%s -s %s.ctl -l uswitch.log -p uswitch.pid" % (subSwitchDir, VS_PROG, SOCKET_NAME)
        
        if debug_uswitch:
            command += " -d -d"

        scrpt.write(command)
        scrpt.close()
        os.system("chmod 755 switch.sh")
        os.system("scp" + SSHOPTS + " switch.sh " + ips[5][i] + ":" + subSwitchDir + "/" + " >> ip_test_log")
        time.sleep(GROUTER_WAIT)
        command = " %s/switch.sh&" % subSwitchDir

        if debug_mode:
            rinput = ""
            while rinput != "y" and rinput != "n" and rinput != "e":
                rinput = raw_input("Enter y/n to start device or e to exit: ")
            if rinput == "y":
                os.system("ssh" + SSHOPTS + ips[5][i] + command)
            elif rinput == "e":
                sys.exit(1)
        else:
            os.system("ssh" + SSHOPTS + ips[5][i] + command)

        time.sleep(GROUTER_WAIT)
        
        if not independent:
            os.system("ssh %s cat %s/uswitch.pid > pid.tmp" % (ips[5][i], subSwitchDir))
            pidIn = open("pid.tmp", "r")
            line = pidIn.readline()
            pidIn.close()
            os.remove("pid.tmp")
            tm.notify(ips[5][i+1].name, line.strip(), ips[5][i])
            
        #os.system("ssh" + SSHOPTS + ips[2][i] + " rm -rf" + command)
        #os.system("rm -rf switch.sh " + configFile)
        print "[OK]"        

    # create the switches for the UML interfaces
    for i in range(0, len(ips[2]), 2):
        for inters in ips[2][i + 1].interfaces:

            for h in range(0, len(ips[3]), 4):
                if (ips[3][h] == ips[2][i + 1].name and ips[3][h + 1] == inters.name):                    
                    break

            for k in range(0, len(ips[4]), 2):
                if(ips[4][k+1] == ips[3][h + 2]):
                    break
            
            # find the specified directory of this specific IP
            for j in range(0, len(ips[0]), 2):
                if (ips[0][j] == ips[2][i]):
                    break

            port_s = ""
            if ips[3][h+3] == "":        
                continue
            elif type(ips[3][h+3]) == str:
                dirname, port_s = ips[3][h+3].split(" ")
                subSwitchDir = "%s/GINI/%s@%s:%s" % (ips[0][j+1], dirname, ips[0][j].split("@")[-1], port_s)
                testcmd = "ssh %s test -e %s/%s.ctl" % (ips[2][i], subSwitchDir, SOCKET_NAME)
                if os.system(testcmd) == 0:
                    print "Using shared Switch from machine %s...\t" % ips[2][i]
                    continue
                print "Starting shared Switch on machine %s...\t" % ips[2][i]        
            else:
                print "Starting Switch on machine %s for %s interface %s...\t" % (ips[2][i], ips[2][i + 1].name, inters.name),
                # create a SWITCH directory on remote machine, under the given specified directory from the IP file
                subSwitchDir = "%s/GINI/%s_Switch_%s" % (ips[0][j + 1], ips[2][i + 1].name, inters.name)

            os.system("ssh" + SSHOPTS + ips[2][i] + " rm -rf " + subSwitchDir)
            time.sleep(GROUTER_WAIT)
            os.system("ssh" + SSHOPTS + ips[2][i] + " mkdir " + subSwitchDir)
            
            ### ------- execute ---------- ###
            # create script files to run on remote machines
            scrpt = open("switch.sh", 'w')

            if port_s:
                newport = port_s
            else:
                newport = ips[3][h + 3]

            remoteIP = ips[4][k]
            if remoteIP.find("@") >= 0:
                newremote = remoteIP.split("@")[1]
            else:
                newremote = remoteIP

            command = "cd %s/\n%s -s %s.ctl -l uswitch.log -p uswitch.pid -u %s -r %s" % (subSwitchDir, VS_PROG, SOCKET_NAME, newport, newremote)
           
            if debug_uswitch:
                command += " -d -d"

            scrpt.write(command)
            scrpt.close()
            os.system("chmod 755 switch.sh")
            os.system("scp" + SSHOPTS + " switch.sh " + ips[2][i] + ":" + subSwitchDir + "/" + " >> ip_test_log")
            time.sleep(GROUTER_WAIT)
            command = " %s/switch.sh&" % subSwitchDir

            if debug_mode:
                rinput = ""
                while rinput != "y" and rinput != "n" and rinput != "e":
                    rinput = raw_input("Enter y/n to start device or e to exit: ")
                if rinput == "y":
                    os.system("ssh" + SSHOPTS + ips[2][i] + command)
                elif rinput == "e":
                    sys.exit(1)
            else:
                os.system("ssh" + SSHOPTS + ips[2][i] + command)

            time.sleep(GROUTER_WAIT)
            #os.system("ssh" + SSHOPTS + ips[2][i] + " rm -rf" + command)
            #os.system("rm -rf switch.sh " + configFile)
            print "[OK]"
    # create the switches for the router interfaces
    for i in range(0, len(ips[1]), 2):
        for inters in ips[1][i + 1].netIF:

            for h in range(0, len(ips[3]), 4):
                if (ips[3][h] == ips[1][i + 1].name and ips[3][h + 1] == inters.name):
                    break

            if ips[3][h+3] == "":
                continue

            for k in range(0, len(ips[4]), 2):
                if(ips[4][k+1] == ips[3][h + 2]):
                    break

            for j in range(0, len(ips[0]), 2):
                if (ips[0][j] == ips[1][i]):
                    break
            
            socketName = "%s/GINI/Shared_Switch@%s:%s/%s.ctl" % (ips[0][j+1], ips[0][j].split("@")[-1], ips[3][h+3], SOCKET_NAME)
            if os.system("ssh %s test -e %s" % (ips[1][i], socketName)) == 0:
                print "Using shared Switch from machine %s...\t" % ips[1][i]
                continue
            print "Starting Switch on machine %s for %s interface %s...\t" % (ips[1][i], ips[1][i + 1].name, inters.name),
            # create directory on remote machine
            subSwitchDir = "%s/GINI/%s_Switch_%s" % (ips[0][j + 1], ips[1][i + 1].name, inters.name)
            os.system("ssh" + SSHOPTS + ips[1][i] + " rm -rf " + subSwitchDir)
            time.sleep(GROUTER_WAIT)
            os.system("ssh" + SSHOPTS + ips[1][i] + " mkdir " + subSwitchDir)

            ### ------- execute ---------- ###
            # create script files to run on remote machines
            scrpt = open("switch.sh", 'w')

            remoteIP = ips[4][k]
            if remoteIP.find("@") >= 0:
                newremote = remoteIP.split("@")[1]
            else:
                newremote = remoteIP

            command = "cd %s/\n%s -s %s.ctl -l uswitch.log -p uswitch.pid -u %d -r %s" % (subSwitchDir, VS_PROG, SOCKET_NAME, ips[3][h + 3], newremote)

            if debug_uswitch:
                command += " -d -d"

            scrpt.write(command)
            scrpt.close()
            os.system("chmod 755 switch.sh")
            os.system("scp" + SSHOPTS + " switch.sh " + ips[1][i] + ":" + subSwitchDir + "/" + " >> ip_test_log")
            time.sleep(GROUTER_WAIT)
            command = " %s/switch.sh&" % subSwitchDir

            if debug_mode:
                rinput = ""
                while rinput != "y" and rinput != "n" and rinput != "e":
                    rinput = raw_input("Enter y/n to start device or e to exit: ")
                if rinput == "y":
                    os.system("ssh" + SSHOPTS + ips[1][i] + command)
                elif rinput == "e":
                    sys.exit(1)
            else:
                os.system("ssh" + SSHOPTS + ips[1][i] + command)

            time.sleep(GROUTER_WAIT)
            os.system("ssh" + SSHOPTS + ips[1][i] + " rm -rf" + command)
            os.system("rm -rf switch.sh ")
            print "[OK]"

    # now that the switches are started, start the routers
    print "\nStarting GINI Routers..."
    success = createVR(myGINI, options, ips) and success
    # now start the umls
    print "\nStarting GINI UMLs..."
    success = createVM(myGINI, options, ips) and success
    return success


# distribute and start routers
def createVR(myGINI, options, ips):
    "create router config file, and start the router"
    logOut = file(LOG_FILE, 'a')
#    rhandle = open('%s/tmp/remote_routers' % os.environ["GINI_HOME"], 'w')

    if not independent:
        sys.stdout = open("/dev/null", "w")
        tm = Pyro.core.getProxyForURI(uri2)
        sys.stdout = sys.__stdout__

    for i in range(0, len(ips[1]), 2):
        # find the specified directory on the remote machine
        for j in range(0, len(ips[0]), 2):
            if (ips[0][j] == ips[1][i]):
                break

        print "Starting Router %s on machine %s...\t" % (ips[1][i + 1].name, ips[1][i]),
#        rhandle.write(ips[1][i + 1].name + " " + ips[1][i] + "\n")
        sys.stdout.flush()
        ### ------ config ---------- ###
        # create the router directory
        subRouterDir = "%s/GINI/%s" % (ips[0][j + 1], ips[1][i + 1].name)
        os.system("ssh" + SSHOPTS + ips[1][i] + " rm -rf " + subRouterDir)
        time.sleep(GROUTER_WAIT)
        os.system("ssh" + SSHOPTS + ips[1][i] + " mkdir " + subRouterDir)
        configFile = "%s.conf" % GR_PROG
        # create the config file
        configOut = open(configFile, "w")
        for nwIf in ips[1][i + 1].netIF:
            remote_target = ""
            isSwitch = False
            sharedPort = ""
            if nwIf.target.find("Switch") >= 0:
                isSwitch = True
            for k in range(0, len(ips[3]), 4):
                if ips[3][k] == nwIf.target:
                    if not sharedPort and ips[3][k+2] == ips[1][i+1].name:
                        sharedPort = ips[3][k+3]                        
                    if isSwitch:                        
                        ips[3][k+1] = nwIf.network
            for m in range(0, len(ips[4]), 2):
                if ips[4][m+1] == nwIf.target:
                    remote_target = ips[4][m]
                    break
            if remote_target == ips[0][j]:
                if isSwitch:
                    socketName = "%s/GINI/%s/%s.ctl" % (ips[0][j+1], nwIf.target, SOCKET_NAME)
                else:
                    socketName = "%s/GINI/%s/gini_socket_%s.ctl" % (ips[0][j + 1], ips[1][i + 1].name, nwIf.name);
            else:
                if type(sharedPort) == str:
                    sharedPort = sharedPort.split(" ")[-1]
                socketName = "%s/GINI/Shared_Switch@%s:%s/%s.ctl" % (ips[0][j+1], ips[0][j].split("@")[-1], sharedPort, SOCKET_NAME)
                if os.system("ssh %s test -e %s" % (ips[1][i], socketName)):
                    socketName = "%s/GINI/%s_Switch_%s/%s.ctl" % (ips[0][j + 1], ips[1][i + 1].name, nwIf.name, SOCKET_NAME);

            configOut.write(getVRIFOutLine(nwIf, socketName))
        configOut.close()
        ### ------- execute ---------- ###
        # go to the router directory to execute the command
        scrpt = open("router.sh", 'w')
        command = "cd %s/\n%s --config=%s.conf --interactive=1 %s" % (subRouterDir, GR_PROG, GR_PROG, ips[1][i + 1].name)
        if debug_mode:
            print command
        scrpt.write(command)
        scrpt.close()
        os.system("chmod 755 router.sh")
        os.system("scp" + SSHOPTS + configFile + " router.sh " + ips[1][i] + ":" + subRouterDir + "/" + " >> ip_test_log")
        command = "screen -d -m "
        if (SCREEN_LOG):
            command += "-L "
        command += "-S %s ssh%s%s -t %s/router.sh" % (ips[1][i + 1].name, SSHOPTS, ips[1][i], subRouterDir)

        if debug_mode:
            rinput = ""
            while rinput != "y" and rinput != "n" and rinput != "e":
                rinput = raw_input("Enter y/n to start device or e to exit: ")
            if rinput == "y":
                os.system(command)
            elif rinput == "e":
                sys.exit(1)
        else:
            os.system(command)

        if not independent:
            tm.notify(ips[1][i+1].name, "", ips[1][i])

        time.sleep(GROUTER_WAIT)
#        os.system("ssh" + SSHOPTS + ips[1][i] + " rm -rf " + subRouterDir + "/router.sh")
        os.system("rm -rf router.sh " + configFile)
        print "[OK]"
    logOut.close()
#    rhandle.close()
    return True

# distribute and start the umls
def createVM(myGINI, options, ips):
    "create UML config file, and start the UML"

    if not independent:
        sys.stdout = open("/dev/null", "w")
        tm = Pyro.core.getProxyForURI(uri2)
        sys.stdout = sys.__stdout__

    logOut = file(LOG_FILE, 'a')
#    rhandle = open('%s/tmp/remote_UMLs', 'w')
    for i in range(0, len(ips[2]), 2):
        print "Starting UML %s on machine %s...\t" % (ips[2][i + 1].name, ips[2][i]),
#        rhandle.write(ips[2][i + 1].name + " " + ips[2][i] + "\n")
        for j in range(0, len(ips[0]), 2):
            if (ips[0][j] == ips[2][i]):
                break
        # create the UML directory
        sys.stdout.flush()
        subUMLDir = "%s/GINI/%s" % (ips[0][j + 1], ips[2][i + 1].name)
        os.system("ssh" + SSHOPTS + ips[2][i] + " rm -rf " + subUMLDir)
        time.sleep(GROUTER_WAIT)
        os.system("ssh" + SSHOPTS + ips[2][i] + " mkdir " + subUMLDir)
        # create command line
        command = createUMLCmdLine(ips[2][i + 1])
        ### ---- process the UML interfaces ---- ###
        # it creates one config for each interface in the current directory
        # and returns a string to be attached to the UML exec command line
        for nwIf in ips[2][i + 1].interfaces:
            for k in range(0, len(ips[3]), 4):
                if ips[3][k+2] == ips[2][i + 1].name:
                    break
            socketName = "%s/GINI/Shared_Switch@%s:%s/%s.ctl" % (ips[0][j+1], ips[0][j].split("@")[-1], ips[3][k+3], SOCKET_NAME)
            if os.system("ssh %s test -e %s" % (ips[2][i], socketName)):
                # name the socket, as per the specified switch
                socketName = "%s/GINI/%s_Switch_%s/%s.ctl" % (ips[0][j + 1], ips[2][i + 1].name, nwIf.name, SOCKET_NAME)
                # since "test" command returns 0 on success
                if os.system("ssh %s test -e %s" % (ips[2][i], socketName)):
                    if ips[3][k].find("Router") >= 0:
                        socketName = "%s/GINI/%s/gini_socket_%s.ctl" % (ips[0][j + 1], ips[3][k], ips[3][k+1])
                    else:
                        socketName = "%s/GINI/%s/gini_socket.ctl" % (ips[0][j + 1], ips[3][k])
            configFile = "%s.sh" % nwIf.name
            # create the config file
            configOut = open(configFile, "w")
            configOut.write("ifconfig %s " % nwIf.name)
            configOut.write("%s\n" % nwIf.ip)

            for route in nwIf.routes:
                if ips[3][k].find("Switch") >= 0:
                    redirect_net = ips[3][k+1]
                    if route.dest == redirect_net:
                        continue
                configOut.write("route add -%s %s " % (route.type, route.dest))
                configOut.write("netmask %s " % route.netmask)
                configOut.write("gw %s\n" % route.gw)
            configOut.close()
            os.system("chmod 755 " + configFile)
            # prepare the output line
            outLine = "%s=daemon,%s,unix," % (nwIf.name, nwIf.mac)
            outLine += socketName
            command += "hostfs=$GINI_HOME %s " % outLine
            scrpt = open("uml.sh", 'w')
            # because the uml looks for a MAC_ADRS.sh file, we move it using this script
            scrptcmd = "cd %s/\nmv %s $GINI_HOME/tmp/%s.sh" % (subUMLDir, configFile, nwIf.mac.upper())
            scrpt.write(scrptcmd)
            scrpt.close()
            os.system("chmod 755 uml.sh")
            os.system("scp" + SSHOPTS + configFile + " uml.sh " + ips[2][i] + ":" + subUMLDir + "/" + " >> ip_test_log")
            time.sleep(GROUTER_WAIT)
            runscrpt = " %s/uml.sh&" % subUMLDir
            os.system("ssh" + SSHOPTS + ips[2][i] + runscrpt)
            
            if os.system("ssh %s test -e '$GINI_HOME'/tmp/UML_bak" % ips[2][i]):
                os.system("ssh %s mkdir '$GINI_HOME'/tmp/UML_bak" % ips[2][i])
            os.system("ssh %s cp '$GINI_HOME'/tmp/%s.sh '$GINI_HOME'/tmp/UML_bak" % (ips[2][i], nwIf.mac.upper()))            
    
            time.sleep(GROUTER_WAIT)
            os.system("ssh" + SSHOPTS + ips[2][i] + " rm -rf" + runscrpt)
            os.system("rm -rf uml.sh " + configFile)
        ### ------- execute ---------- ###
        # go to the UML directory to execute the command
        scrpt = open("startit.sh", 'w')
        cmd = "cd %s\n%s" % (subUMLDir, command)
        scrpt.write(cmd)
        scrpt.close()
        os.system("chmod 755 startit.sh")
        os.system("scp" + SSHOPTS + "startit.sh " + ips[2][i] + ":" + subUMLDir + "/" + " >> ip_test_log")
        time.sleep(GROUTER_WAIT)
        startUml = "screen -d -m -S %s ssh%s%s -t %s/startit.sh" % (ips[2][i + 1].name, SSHOPTS, ips[2][i], subUMLDir)

        if debug_mode:
            rinput = ""
            while rinput != "y" and rinput != "n" and rinput != "e":
                rinput = raw_input("Enter y/n to start device or e to exit: ")
            if rinput == "y":        
                    os.system(startUml)
            elif rinput == "e":
                sys.exit(1)
        else:
            os.system(startUml)

        time.sleep(UML_WAIT_DELAY)
        
        os.system("rm -rf startit.sh")
        print "[OK]"
    logOut.close()
#    rhandle.close()

    if not independent:                  
        for i in range(0, len(ips[2]), 2):
            tm.notify(ips[2][i+1].name, "", ips[2][i])

    return True

# taken from gloader
def getVRIFOutLine(nwIf, socketName):
    "convert the router network interface specs into a string"
    outLine = "ifconfig add %s " % nwIf.name
    outLine += "-socket %s " % socketName
    outLine += "-addr %s " % nwIf.ip
    outLine += "-network %s " % nwIf.network
    outLine += "-hwaddr %s " % nwIf.nic
    if (nwIf.gw):
        outLine += "-gw %s " % nwIf.gw
    if (nwIf.mtu):
        outLine += "-mtu %s " % mwIf.mtu
    outLine += "\n"
    for route in nwIf.routes:
        outLine += "route add -dev %s " % nwIf.name
        outLine += "-net %s " % route.dest
        outLine += "-netmask %s " % route.netmask
        if (route.nexthop):
            outLine += "-gw %s" % route.nexthop
        outLine += "\n"
    return outLine

# taken from gloader
def createUMLCmdLine(uml):
    command = ""
    ## uml binary name
    if (uml.kernel):
        command += "%s " % uml.kernel
    else:
        command += "%s " % VM_PROG_BIN
    ## uml ID
    command += "umid=%s " % uml.name
    ## handle the file system option
    # construct the cow file name
    fileSystemName = getBaseName(uml.fileSystem.name)
    fsCOWName = "%s.cow" % fileSystemName
    if (uml.fileSystem.type.lower() == "cow"):
        command += "ubd0=%s,$GINI_HOME/%s " % (fsCOWName, fileSystemName)
    else:
        command += "ubd0=%s " % uml.fileSystem.name
    ## handle the mem option
    if (uml.mem):
        command += "mem=%s " % uml.mem
    ## handle the boot option
    if (uml.boot):
        command += "con0=%s " % uml.boot
    return command

# taken from gloader
def getBaseName(pathName):
    "Extract the filename from the full path"
    pathParts = pathName.split("/")
    return pathParts[len(pathParts)-1]

# stop the network
def undistGINI(myGINI, options, ips):

    #don't use kill -9 -1
    brute_force = False

    os.system("rm -rf ip_test_log")
    print "\nTerminating switches..."
    print "\nTerminating routers..."
    print "\nTerminating UMLs..."
    print "\nCleaning the interprocess message queues"
#    batch_ipcrm.clean_ipc_queues()

    if brute_force:
    # since we are working on remote machines, we don't care about
    # the process there, so, we just ssh and kill -9 -1 (this kills
    # all the process linked to the user
        for i in range(0, len(ips[0]), 2):
            os.system("ssh" + SSHOPTS + " " + ips[0][i] +  " kill -9 -1")
            if (not options.keepOld):
                print "\nDeleting GINI related files on remote machine %s...\n" % ips[0][i]
                command = " rm -rf %s/GINI" % ips[0][i + 1]
                os.system("ssh" + SSHOPTS + " " + ips[0][i] + command)
        return True
    else:
        for i in range(0, len(ips[0]), 2):
            os.system("ssh" + SSHOPTS + " " + ips[0][i] +  " killall -13 -u %s -q uswitch" % os.getenv("USER"))
            os.system("ssh" + SSHOPTS + " " + ips[0][i] +  " killall -u %s -q grouter glinux" % os.getenv("USER"))
            if (not options.keepOld):
                print "\nDeleting GINI related files on remote machine %s...\n" % ips[0][i]
                time.sleep(0.5)
                command = " rm -rf %s/GINI" % ips[0][i + 1]
                os.system("ssh" + SSHOPTS + " " + ips[0][i] + command)
        return True


# adapted from gloader with modifications
def checkProcAlive(procName, ipdirs):
    alive = False
    # grep the GINI processes
    command = " ps aux | grep %s > %s" % (procName, GINI_TMP_FILE)
    for i in range(0, len(ipdirs), 2):
        os.system("ssh" + SSHOPTS + ipdirs[i] + command)
        # analyse the grepped output
        inFile = open(GINI_TMP_FILE)
        line = inFile.readline()
        while (line):
            if (line.find("grep") == -1):
                # don't consider the "grep" line
                userName = os.environ["USER"]
                lineParts = line.split()
                if (lineParts[0] == userName):
                    # consider only the instances with the current user
                    alive = True
                    print "There is a live GINI %s on machine %s" % (procName, ipdirs[i])
            line = inFile.readline()
        inFile.close()
        # clean up
        os.remove(GINI_TMP_FILE)
    return alive

# adapted from gloader with modifications
def writeSrcFile(options):
    "write the configuration in the setup file"
    outFile = open(SRC_FILENAME, "w")
    outFile.write("%s\n" % options.xmlFile)
    outFile.write("%s\n" % options.switchDir)
    outFile.write("%s\n" % options.routerDir)
    outFile.write("%s\n" % options.umlDir)
    outFile.write("%s\n" % options.binDir)
    outFile.write("%s\n" % options.ipSpecs)
    outFile.close()

# taken from gloader
def deleteSrcFile():
    "delete the setup file"
    if (os.access(SRC_FILENAME, os.W_OK)):
        os.remove(SRC_FILENAME)
    else:
        print "Could not delete the GINI setup file"

# adapted from gloader with modifications
def checkAliveGini(ips):
    "check any of the gini components already running"
    # Modified to check every machine in our ipSpecs file
    result = False
    if checkProcAlive(VS_PROG_BIN, ips[0]):
        result = True
    if checkProcAlive(VM_PROG_BIN, ips[0]):
        result = True
    if checkProcAlive(GR_PROG_BIN, ips[0]):
        result = True
    return result


#### -------------- MAIN start ----------------####

# create the program processor. This
# 1. accepts and process the command line options
# 2. creates XML processing engine, that in turn
#    a) validates the XML file
#    b) extracts the DOM object tree
#    c) populates the GINI network class library
#    d) performs some semantic/syntax checkings on
#       the extracted specification
#    e) validates the IP file for distribution

old = False

myProg = Start(sys.argv[0], SRC_FILENAME)
if (not myProg.processOptions(sys.argv[1:])):
    sys.exit(1)
options = myProg.options

# Get the valid IPs and directories from the ipSpecs file
# Also check if the IPs and directories are valid
# we validate by: scp a file into given machine and directory
# ssh and remove the file. Once this is validated, we don't
# have to error-check these operations anymore
if old:
    ipfilehandle = open(options.ipSpecs, 'r')
    lines = ipfilehandle.readlines()
    iptest = open("ip_test_log", 'w')
    iptest.close()
    ginitest = open("gini_ip_test", 'w')
    ginitest.write("This is a test file\nIt should not be here\nIt should have been deleted automatically\nDelete it if you can read this!!!")
    ginitest.close()
    ipdircombos = []
    res = False
    for line in lines:
        a = line.split("\n")
        b = a[0].split(":")
        ipdircombos.append(b[0])
        ipdircombos.append(b[1])
        if ((not myProg.undistOpt) or (not options.keepOld)):
            os.system("ssh" + SSHOPTS + b[0] + " rm -rf " + b[1] + "/GINI")
            time.sleep(GROUTER_WAIT)
            os.system("ssh" + SSHOPTS + b[0] + " mkdir " + b[1] + "/GINI")
        i = os.system("scp" + SSHOPTS + "gini_ip_test " + a[0] + "/GINI/ >> ip_test_log")
        if (not i == 0):
            print "Problem with machine or directory %s" % a[0]
            res = True
        if (i == 0):
            os.system("ssh" + SSHOPTS + b[0] + " rm -rf " + b[1] + "/GINI/gini_ip_test >> ip_test_log")
            print "Machine and directory valid on %s" % a[0]
    os.system("rm -rf gini_ip_test")
    ipfilehandle.close()
    if (res):
        sys.exit(1)

    # get the populated GINI network class
    # its structure is the same as the XML specification
    myGINI = myProg.giniNW

    # We don't distribute switches
    if (len(myGINI.switches) > 0):
        print "\nCannot distriute switches...sorry"
        print "These cannot be in the topology"
        sys.exit(1)

    # Let the user know about the number of IPs
    total_ips_req = len(myGINI.vr) + len(myGINI.vm)
    total_ips_giv = len(ipdircombos) / 2
#    if (total_ips_req > total_ips_giv):
#        print "\nThe given IPs aren't enough"
#        print "There will be more than one GINI component on some machines\n"

    ipvrcombos = []
    ipvmcombos = []
    ipcompcombos = []
    j = 0
    for i in range(len(myGINI.vr)):
        ipvrcombos.append(ipdircombos[j])
        ipvrcombos.append(myGINI.vr[i])
        ipcompcombos.append(ipdircombos[j])
        ipcompcombos.append(myGINI.vr[i].name)
        j = (j + 2) % len(ipdircombos)
    for i in range(len(myGINI.vm)):
        ipvmcombos.append(ipdircombos[j])
        ipvmcombos.append(myGINI.vm[i])
        ipcompcombos.append(ipdircombos[j])
        ipcompcombos.append(myGINI.vm[i].name)
        j = (j + 2) % len(ipdircombos)

else:
    if debug_mode:
        print "checkpoint 1"
    ipdircombos = []
    ipvrcombos = []
    ipvmcombos = []
    ipvscombos = []
    ipcompcombos = []
    dev_dic = {}
    hosts = []
    rdfile = options.xmlFile[0:len(options.xmlFile)-4] + "_rdist"
    rdhandle = open(rdfile, "r")
    for line in rdhandle.readlines():
        parts = line.strip().split(",")

        if int(parts[1]):
            if hosts.count(parts[2]):
                pass
            else:
                hosts.append(parts[2])
            for i in range(3, len(parts)):
                dev_dic[parts[i]] = parts[2].split(":")[0]

    rdhandle.close()
    
    ginitest = open("gini_ip_test", 'w')
    ginitest.write("This is a test file\nIt should not be here\nIt should have been deleted automatically\nDelete it if you can read this!!!")
    ginitest.close()
    res = False
    if debug_mode:
        print "checkpoint 2"
    for host in hosts:
        hostpath = host.split(":")
        ipdircombos.append(hostpath[0])
        if len(hostpath) < 2:
            hostlogin = hostpath[0].split("@")
            if len(hostlogin) < 2:
                whoami = os.getenv("USER")
            else:
                whoami = hostlogin[0]

            newpath = "/home/%s/gtemp" % whoami
            hostpath.append(newpath)
            host += ":" + hostpath[1]
                    
            if not myProg.undistOpt:
                print "Warning, invalid remote path specified, defaulting to %s" % newpath
                os.system("ssh" + SSHOPTS + hostpath[0] + " mkdir " + hostpath[1] + " 2> /dev/null")
            else:
                #os.system("ssh" + SSHOPTS + hostpath[0] + " rm -rf " + hostpath[1] + " 2> /dev/null")
                pass

        ipdircombos.append(hostpath[1])

        if ((not myProg.undistOpt) and (not options.keepOld)):
            os.system("ssh" + SSHOPTS + hostpath[0] + " rm -rf " + hostpath[1] + "/GINI")
            time.sleep(GROUTER_WAIT)
            os.system("ssh" + SSHOPTS + hostpath[0] + " mkdir " + hostpath[1] + "/GINI")
        i = os.system("scp" + SSHOPTS + "gini_ip_test " + host + "/GINI/ >> ip_test_log")
        if (not i == 0):
            print "Problem with machine or directory %s" % host
            res = True
        if (i == 0):
            os.system("ssh" + SSHOPTS + hostpath[0] + " rm -rf " + hostpath[1] + "/GINI/gini_ip_test >> ip_test_log")
            print "Machine and directory valid on %s" % host
    os.system("rm -rf gini_ip_test")
    if (res):
        sys.exit(1)

    # get the populated GINI network class
    # its structure is the same as the XML specification
    myGINI = myProg.giniNW

    # We don't distribute wireless components
    if len(myGINI.vwr) > 0 or len(myGINI.vmb) > 0:
       print "\nCannot distriute wireless devices...sorry"
       print "These cannot be in the topology"
       sys.exit(1)

    # Let the user know about the number of IPs
    total_ips_req = len(myGINI.vr) + len(myGINI.vm)
    total_ips_giv = len(ipdircombos) / 2
#    if (total_ips_req > total_ips_giv):
#        print "\nThe given IPs aren't enough"
#        print "There will be more than one GINI component on some machines\n"

    if debug_mode:
        print "checkpoint 3"
    for router in myGINI.vr:
        ipvrcombos.append(dev_dic[router.name])
        ipvrcombos.append(router)
        ipcompcombos.append(dev_dic[router.name])
        ipcompcombos.append(router.name)
                    
    for uml in myGINI.vm:
        ipvmcombos.append(dev_dic[uml.name])
        ipvmcombos.append(uml)
        ipcompcombos.append(dev_dic[uml.name])
        ipcompcombos.append(uml.name)
        
    for switch in myGINI.switches:
        ipvscombos.append(dev_dic[switch.name])
        ipvscombos.append(switch)
        ipcompcombos.append(dev_dic[switch.name])
        ipcompcombos.append(switch.name)

# Calculate switch port properties. If there is a
# link in the GINI topology between two components,
# then the switches for these components must have
# the same port number and their respective remote
# addresses should refer to each other
if debug_mode:
    print "checkpoint 4"
ipports = []
for i in myGINI.vm:
    for j in i.interfaces:
        ipports.append(i.name)
        ipports.append(j.name)
        ipports.append(j.target)
        ipports.append(0)
for i in myGINI.vr:
    for j in i.netIF:
        ipports.append(i.name)
        ipports.append(j.name)
        ipports.append(j.target)
        ipports.append(0)
for i in myGINI.switches:
    for j in range(2, len(ipports), 4):
        if ipports[j] == i.name:
            ipports.append(i.name)
            ipports.append("")
            ipports.append(ipports[j-2])
            ipports.append(0)

if None:
    print ipdircombos
    print ipvrcombos
    print ipvmcombos
    print ipports
    print ipcompcombos
    print ipvscombos

    answer = ""
    while answer != "y" and answer != "n":
        answer = raw_input("Continue?")
    if answer == "n":
        sys.exit(1)

# find available ports such that they match on both remote machines
# switches are initialized with port and remote ip fields but the
# host and remote ip are only talking to the same port (ie. if the
# host machine has a switch on port x then the remote machine must
# have a listening switch on port x as well
if debug_mode:
    print "checkpoint 5"
if (not myProg.undistOpt):
    switchport = 1115
    spcombos = {}
    for i in range(3, len(ipports), 4):
        if ipports[i] == 0:
            j = 1
            # find the machines of the source and destination
            while (not ipports[i - 3] == ipcompcombos[j]):
                j += 2
            k = 1
            while (not ipports[i - 1] == ipcompcombos[k]):
                k += 2
            os.system("ssh" + SSHOPTS + ipcompcombos[j - 1] + " netstat -anp > m1ports 2>&1")
            os.system("ssh" + SSHOPTS + ipcompcombos[k - 1] + " netstat -anp > m2ports 2>&1")
            check = True
            while (check):
                command = "grep -w %d m1ports >> ip_test_log" % switchport
                m1 = os.WEXITSTATUS(os.system(command))
                command = "grep -w %d m2ports >> ip_test_log" % switchport
                m2 = os.WEXITSTATUS(os.system(command))
                if (m1 == 1 and m2 == 1):
                    # keep interconnected switch ports consistent
                    if ipports[i-3].find("Switch") >= 0:
                        if spcombos.has_key(ipports[i-3]):
                            ipports[i] = spcombos[ipports[i-3]] # use shared port
                            switchport -= 1 # will be incremented later
                        else:
                            ipports[i] = switchport
                            spcombos[ipports[i-3]] = switchport # define new shared port        
                    elif ipports[i-1].find("Switch") >= 0:
                        if spcombos.has_key(ipports[i-1]):
                            ipports[i] = spcombos[ipports[i-1]]
                            switchport -= 1
                        else:
                            ipports[i] = switchport
                            spcombos[ipports[i-1]] = switchport
                    else:
                        ipports[i] = switchport
                        for x in range(3, len(ipports), 4):
                            # find reverse connections
                            if (ipports[i - 3] == ipports[x - 1] and ipports[i - 1] == ipports[x - 3]):
                                break
                        ipports[x] = switchport
                    switchport += 1
                    check = False
                else:
                    switchport += 1
            os.system("rm -rf m1ports m2ports")

if not old:
    if debug_mode:
        print "checkpoint 6"
    for i in range(0, len(ipports), 4):
        source = ipports[i]
        destination = ipports[i+2]
        # if machine of source and machine of destination are the same

        if dev_dic[source] == dev_dic[destination]:
            # signal to not create a switch between elements running on the same machine 
            if source.find("Router") >= 0 or destination.find("Router") >= 0:
                ipports[i+3] = ""   # clear port number
            elif source.find("Switch") >= 0 or destination.find("Switch") >= 0:
                ipports[i+3] = ""
        elif source.find("Switch") >= 0:
            for j in range(0, len(ipcompcombos), 2):
                if ipcompcombos[j+1] == destination:
                    ipports[i+1] = ipcompcombos[j]  # provide remote location instead of interface
                    break
        elif source.find("UML") >= 0:
            ipports[i+3] = "Shared_Switch %d" % ipports[i+3]


# Store the mappings so we can pass them around
ips = []
# Zeroth element is IP and Directory tuples
ips.append(ipdircombos)
# First element is IP and Router tuples
ips.append(ipvrcombos)
# Second element is IP and UML tuples
ips.append(ipvmcombos)
# Third element is Switch port configurations
ips.append(ipports)
# Forth element is IP and component tuples
# UMLs and Router in one list
ips.append(ipcompcombos)

ips.append(ipvscombos)

if debug_mode:
    if debug_mode:
        print "checkpoint 7"
    print ips

    answer = ""
    while answer != "y" and answer != "n":
        answer = raw_input("Continue?")
    if answer == "n":
        sys.exit(1)

# reset the log file
if (os.access(LOG_FILE, os.F_OK)):
    os.remove(LOG_FILE)

# distribute or undistribute GINI network
print ""
if (myProg.undistOpt):
    # terminate the current distributed specification
    print "Terminating GINI network..."
    success = undistGINI(myGINI, options, ips)
    if (success):
        print "\nGINI network is undistributed and terminated!!\n"
    else:
        print "\nThere are errors in GINI network termination"
        print "Check the logfile %s for more details" % LOG_FILE
        print "You might have to terminate the orphaned processes manually\n"
        sys.exit(1)
else:
    # create a distributed GINI instance
    if (not options.keepOld):
        # fail if a GINI already alive
        if checkAliveGini(ips):
            sys.exit(1)
    # create network with current specifcation
    print "Creating and distributing a GINI network..."
    success = distGINI(myGINI, options, ips)
    writeSrcFile(options)
    if (success):
        print "\nGINI network up, running and distributed!!\n"
    else:
        print "\nProblem in creating GINI network"
        print "Check the log file %s for details" % LOG_FILE
        print "** Run gdist -y to terminate the partially started ",
        print "GINI instance before starting another one **\n"
        sys.exit(1)
sys.exit(0)
