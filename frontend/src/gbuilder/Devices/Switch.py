from Core.Device import *

class Switch(Device):
    type = "Switch"
    
    def __init__(self):
        Device.__init__(self)
        self.setProperty("Hub mode", "False")
#       self.setProperty("mask", "")
#       self.setProperty("subnet", "")
#       self.setProperty("link_subnet", "0")
#       self.setProperty("port", "")
#       self.setProperty("monitor", "")

    def addEdge(self, edge):
        Device.addEdge(self, edge)

        node = edge.getOtherDevice(self)
        if node.type == "UML":
            node.addInterface(self)

    def removeEdge(self, edge):
        Device.removeEdge(self, edge)

        node = edge.getOtherDevice(self)
        if node.type == "UML":
            node.removeInterface(self)
    
    def getTarget(self, node):
        for con in self.edges():
            other = con.getOtherDevice(self)
            if other != node and other.type == "Subnet":
                return other.getTarget(self)
