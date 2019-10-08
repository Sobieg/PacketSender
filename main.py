import sys
import os
import socket
import time
import psutil
import random
from getmac import getmac
from PyQt5 import QtWidgets
import design


class PacketSender(QtWidgets.QMainWindow, design.Ui_PacketSender):
    def __init__(self):
        super().__init__()
        self.setupUi(self)


        #init all slots and signals
        self.refreshNetworkInterfaces()
        self.sendButton.clicked.connect(self.sendBtnHandler)
        # self.tab_L4_Widget.currentChanged['int'].connect(self.spinBoxProtocol.setValue)










        # self.spinBoxSrcPort.setProperty("value", random.randint(0, 65535))  # Random source port
        # BUG: ca
        ## self.spinBoxSEQ.setMaximum(4294967296)  # set max SEQ to 2**32

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

    def sendBtnHandler(self):
        times = self.getTimesSend()
        delay = self.getDelaySend()
        print("pushed button send with times = ", times, " delay = ", delay)
        for i in range(times):
            self.sendPacket()
            time.sleep(delay / 1000)



def main():
    app = QtWidgets.QApplication(sys.argv)
    window = PacketSender()
    window.show()
    app.exec_()


if __name__ == '__main__':
    main()
