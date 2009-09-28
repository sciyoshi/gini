from Core.Device import *

##
# Class: the hub device. Not fully implemented yet
class Hub(Device):
    type="Hub"

    def __init__(self):
        Device.__init__(self)

	self.setProperty("port", "")
	self.setProperty("monitor", "")
        self.setProperty("hub", True)   # use hub mode by default 


