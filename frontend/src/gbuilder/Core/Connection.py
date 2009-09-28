"""The logical connection object that links two devices together"""

from Devices.Bridge import *
from Devices.Firewall import *
from Devices.Hub import *
from Devices.Mobile import *
from Devices.Router import *
from Devices.Subnet import *
from Devices.Switch import *
from Devices.UML import *
from Devices.UML_Android import *
from Devices.UML_FreeDOS import *
from Devices.Wireless_access_point import *
from UI.Edge import *

# The connection rules for building topologies
connection_rule={}
connection_rule[UML.type]=(Switch.type, Subnet.type, Bridge.type, Hub.type)
connection_rule[UML_Android.type]=connection_rule[UML.type]
connection_rule[UML_FreeDOS.type]=connection_rule[UML.type]
connection_rule[Router.type]=(Subnet.type)
connection_rule[Switch.type]=(UML.type, Subnet.type)
connection_rule[Bridge.type]=(UML.type, Subnet.type)
connection_rule[Hub.type]=(UML.type, Subnet.type)
connection_rule[Wireless_access_point.type]=(Mobile.type)
connection_rule[Subnet.type]=(UML.type, Switch.type, Router.type, Bridge.type, Hub.type, Firewall.type)
connection_rule[Mobile.type]=(Wireless_access_point.type)
connection_rule[Firewall.type]=(Subnet.type)

class Connection(Edge):
    type = "Connection"

    def __init__(self, source, dest):
        """
        Create a connection to link devices together.
        """
        Edge.__init__(self, source, dest)
    
    def getOtherDevice(self, node):
        """
        Retrieve the device opposite to node from this connection.
        """
        if self.source == node:
            return self.dest
        return self.source
