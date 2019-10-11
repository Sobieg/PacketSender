import sys
import os
import socket
import time
import psutil
import random
from getmac import getmac
from PyQt5 import QtWidgets, QtCore, QtGui
import design

"Naming objects: " \
"class_tabname_Name"


# TODO:
#         1) change checksums fields from spinboxes to text fields
#         2) merge ipv4 fields in ipv4 and icmp tabs


class PacketSender(QtWidgets.QMainWindow, design.Ui_PacketSender):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        # Load interfecases
        self.statusBar.showMessage("Loading interfaces ...")
        self.refreshNetworkInterfaces()
        self.statusBar.showMessage("Loading interfaces ... done")

        # Generate random source port
        self.statusBar.showMessage("Generating random SRC port ...")
        self.spinBox_tcp_SRCPort.setValue(random.randint(8000, 65535))
        self.spinBox_udp_SRCPort.setValue(self.spinBox_tcp_SRCPort.value())
        self.statusBar.showMessage("Generating random SRC port ... done")

        self.statusBar.showMessage("Ready")

    # Help methods:
    def refreshNetworkInterfaces(self):
        self.comboInterfacesBox.clear()
        addrs = psutil.net_if_addrs()
        for NICname in addrs.keys():
            self.comboInterfacesBox.addItem(NICname)

    def getTimesSend(self):
        return self.timesSpinBox.value()

    def getDelaySend(self):
        return self.delaySpinBox.value()

    def sendPacket(self):
        print("Sent")

    def showBitChange(self, nState, bitname, proto):
        if nState:
            self.statusBar.showMessage(str(proto) + " " + str(bitname) + " bit set")
        else:
            self.statusBar.showMessage(str(proto) + " " + str(bitname) + " bit unset")


    # Slots:
    def sendBtnClicked(self):
        times = self.getTimesSend()
        delay = self.getDelaySend()
        print("pushed button send with times = ", times, " delay = ", delay)
        for i in range(times):
            self.sendPacket()
            time.sleep(delay / 1000)

    def tcpSourcePortChanged(self, nValue):
        # TODO: actually change the value
        self.statusBar.showMessage("Tcp SRC port changed to " + str(nValue), 2000)

    def tcpDestinationPortChanged(self, nValue):
        # TODO: actually change the value
        self.statusBar.showMessage("Tcp DST port changed to " + str(nValue), 2000)

    def tcpSEQNumChanged(self, nValue):
        # TODO: actually change the value
        self.statusBar.showMessage("Tcp SEQ changed to " + str(nValue), 2000)
        
    def tcpACKChanged(self, nValue):
        # TODO: actually change the value
        self.statusBar.showMessage("Tcp ACK changed to " + str(nValue), 2000)

    def tcpDataOffsetChanged(self, nValue):
        # TODO: actually change the value
        self.statusBar.showMessage("Tcp Data Offset changed to " + str(nValue), 2000)

    def tcpRes1Changed(self, nState):
        # TODO: actually change the value
        self.showBitChange(nState, "Res1", "TCP")

    def tcpRes2Changed(self, nState):
        # TODO: actually change the value
        self.showBitChange(nState, "Res2", "TCP")

    def tcpRes3Changed(self, nState):
        # TODO: actually change the value
        self.showBitChange(nState, "Res3", "TCP")

    def tcpRes4Changed(self, nState):
        # TODO: actually change the value
        self.showBitChange(nState, "Res4", "TCP")

    def tcpCWRChanged(self, nState):
        # TODO: actually change the value
        self.showBitChange(nState, "CWR", "TCP")

    def tcpECEChanged(self, nState):
        # TODO: actually change the value
        self.showBitChange(nState, "ECE", "TCP")

    def tcpURGChanged(self, nState):
        # TODO: actually change the value
        self.showBitChange(nState, "URG", "TCP")

    def tcpACKChanged(self, nState):
        # TODO: actually change the value
        self.showBitChange(nState, "ACK", "TCP")

    def tcpPSHChanged(self, nState):
        # TODO: actually change the value
        self.showBitChange(nState, "PSH", "TCP")

    def tcpRSTChanged(self, nState):
        # TODO: actually change the value
        self.showBitChange(nState, "RST", "TCP")

    def tcpSYNChanged(self, nState):
        # TODO: actually change the value
        self.showBitChange(nState, "SYN", "TCP")

    def tcpFINChanged(self, nState):
        # TODO: actually change the value
        self.showBitChange(nState, "FIN", "TCP")


    def tcpWINChanged(self, nValue):
        # TODO: actually change the value
        self.statusBar.showMessage("Tcp WIN changed to " + str(nValue), 2000)

    def tcpChecksumChanged(self, nValue):
        # TODO: actually change the value
        #       dont think that is important print message, that checksum changed
        pass

    def tcpUrgentChanged(self, nValue):
        # TODO: actually change the value
        self.statusBar.showMessage("Tcp Urgent changed to " + str(nValue), 2000)

    def tcpOptionsAddNopsChanged(self, nState):
        # TODO: actually add the nops
        if nState:
            self.statusBar.showMessage("Added two NOP's to the TCP Packet", 2000)
        else:
            self.statusBar.showMessage("Removed two NOP's from the TCP Packet", 2000)

    def tcpOptionsAddTimestampChanged(self, nState):
        if nState:
            self.statusBar.showMessage("Added timestamp to the TCP Packet", 2000)
        else:
            self.statusBar.showMessage("Removed timestamp from the TCP Packet", 2000)

    def tcpDataChanged(self):
        

def main():
    app = QtWidgets.QApplication(sys.argv)
    window = PacketSender()
    window.show()
    app.exec_()


if __name__ == '__main__':
    main()
