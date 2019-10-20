import sys
import os
import socket
import time
import psutil
import random
from scapy.layers import inet, l2

from PyQt5 import QtWidgets, QtCore, QtGui

import design

DEBUG = True #WTF I WANT IFDEF


"Naming objects: " \
"class_tabname_Name"


# TODO: 1) change checksums fields from spinboxes to text fields DONE
# TODO: 2) merge ipv4 fields in ipv4 and icmp tabs DONE
# TODO: 3) MAC from ip DONE
# TODO: 4) generate packet by pressing send button
# TODO: 5) generate new checksum when return pressed in every method _Changed
# TODO: 6) Check values from forms and if it is not changed, use default values
# TODO: 7) Generate packet in separate method and get checksum from it
# TODO: 8) Checksums in the end of generating packet, before sending.


class PacketSender(QtWidgets.QMainWindow, design.Ui_PacketSender):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        # Load interfaces
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

    def sendPacket(self, times, delay):

        frame = l2.Ether()
        ipPacket = inet.IP()

        if (srcmac := self.lineEdit_mac_SRCMAC.text()) != ":::::":
            frame.src = srcmac
        if (dstmac := self.lineEdit_mac_DSTMAC.text()) != ":::::":
            frame.dst = dstmac

        if self.tab_L3_Widget.currentIndex() == 1:  # ICMP
            icmpPacket = inet.ICMP()
            if (ipVer := self.spinBox_icmp_Version.value()) != 0:
                ipPacket.version = ipVer
            if (ihl := self.spinBox_icmp_HeaderLenght.value()) != 0:
                ipPacket.ihl = ihl
            if (tos := self.spinBox_icmp_ToS.value()) != 0:
                ipPacket.tos = tos
            if (len := self.spinBox_icmp_TotalLenght.value()) != 0:
                ipPacket.len = len
            if (id := self.spinBox_icmp_Identifier.value()) != 0:
                ipPacket.id = id
            ipPacket.flags = (int(self.checkBox_icmp_MF.isChecked()) +
                              int(self.checkBox_icmp_DF.isChecked() << 1) +
                              int(self.checkBox_icmp_Res.isChecked() << 2))
            if (frag := self.spinBox_icmp_FragmentOffset.value()) != 0:
                ipPacket.frag = frag
            if (ttl := self.spinBox_icmp_TTL.value()) != 0:
                ipPacket.ttl = ttl
            if (proto := self.spinBox_icmp_Protocol.value()) != 0:
                ipPacket.proto = proto
            # if crc := self.lineEdit_tcp_Checksum.text() != "":
            #     ipPacket.chksum = crc
            if (src := self.lineEdit_icmp_SRCIP.text()) != "...":
                ipPacket.src = src
            if (dst := self.lineEdit_icmp_DSTIP.text()) != "...":
                ipPacket.dst = dst
            opti = [self.checkBox_icmp_options_Copied.isChecked()]
            if (clOpt := self.spinBox_icmp_options_Class.value()) != 0:
                opti.append(clOpt)
            if (nuOpt := self.spinBox_icmp_options_Number.value()) != 0:
                opti.append(nuOpt)
            if (leOpt := self.spinBox_icmp_options_Length.value()) != 0:
                opti.append(leOpt)
            if (daOpt := self.plainTextEdit_icmp_options_Data.toPlainText()) != "":
                opti.append(daOpt)
            # ipPacket.options = opti
            # options not working because idk

            if (type := self.spinBox_icmp_Type.value()) != 0:
                icmpPacket.type = type
            if (code := self.spinBox_icmp_Code.value()) != 0:
                icmpPacket.code = code
            ipPacket = ipPacket / icmpPacket
        else:
            ipPacket = inet.IP()
            if (ipVer := self.spinBox_ipv4_Version.value()) != 0:
                ipPacket.version = ipVer
            if (ihl := self.spinBox_ipv4_IHL.value()) != 0:
                ipPacket.ihl = ihl
            if (tos := (self.spinBox_ipv4_DSCP.value() << 2 + self.spinBox_ipv4_ECN.value())) != 0:  # TODO: check this
                ipPacket.tos = tos
            if (len := self.spinBox_ipv4_TotalLength.value()) != 0:
                ipPacket.len = len
            if (id := self.spinBox_ipv4_Identification.value()) != 0:
                ipPacket.id = id
            ipPacket.flags = (int(self.checkBox_ipv4_MF.isChecked()) +
                              int(self.checkBox_ipv4_DF.isChecked() << 1) +
                              int(self.checkBox_ipv4_Res.isChecked() << 2))
            if (frag := self.spinBox_ipv4_FragmentOffset.value()) != 0:
                ipPacket.frag = frag
            if (ttl := self.spinBox_ipv4_TTL.value()) != 0:
                ipPacket.ttl = ttl
            if (proto := self.spinBox_ipv4_Protocol.value()) != 0:
                ipPacket.proto = proto
            # if (crc := self.lineEdit_ipv4_Checksum.text() )!= "":
            #     ipPacket.chksum = crc
            if (src := self.lineEdit_ipv4_SRCIP.text()) != "...":
                ipPacket.src = src
            if (dst := self.lineEdit_ipv4_DSTIP.text()) != "...":
                ipPacket.dst = dst
            opti = [self.checkBox_ipv4_options_Copied.isChecked()]
            if (clOpt := self.spinBox_ipv4_options_Class.value()) != 0:
                opti.append(clOpt)
            if (nuOpt := self.spinBox_ipv4_options_Number.value()) != 0:
                opti.append(nuOpt)
            if (leOpt := self.spinBox_ipv4_options_Length.value()) != 0:
                opti.append(leOpt)
            if (daOpt := self.plainTextEdit_ipv4_options_Data.toPlainText()) != "":
                opti.append(daOpt)
            # ipPacket.options = opti
            # Options not working because of idk fixme

            if self.tab_L4_Widget.currentIndex() == 0:  # TCP
                tcpPacket = inet.TCP()
                if (srcp := self.spinBox_tcp_SRCPort.value()) != 0:
                    tcpPacket.sport = srcp
                if (dstp := self.spinBox_tcp_DSTPort.value()) != 0:
                    tcpPacket.dport = dstp
                if (seq := self.spinBox_tcp_SEQ.value()) != 0:
                    tcpPacket.seq = seq
                if (ack := self.spinBox_tcp_ACK.value()) != 0:
                    tcpPacket.ack = ack
                if (dataoffs := self.spinBox_tcp_DataOffset.value()) != 0:
                    tcpPacket.dataofs = dataoffs
                tcpPacket.reserved = (int(self.checkBox_tcp_Res3.isChecked() << 2) +
                                      int(self.checkBox_tcp_Res2.isChecked() << 1) +
                                      int(self.checkBox_tcp_Res1.isChecked() << 0))
                tcpPacket.flags = (int(self.checkBox_tcp_Res4.isChecked()<< 8) +
                                   int(self.checkBox_tcp_CWR.isChecked() << 7) +
                                   int(self.checkBox_tcp_ECE.isChecked() << 6) +
                                   int(self.checkBox_tcp_URG.isChecked() << 5) +
                                   int(self.checkBox_tcp_ACK.isChecked() << 4) +
                                   int(self.checkBox_tcp_PSH.isChecked() << 3) +
                                   int(self.checkBox_tcp_RST.isChecked() << 2) +
                                   int(self.checkBox_tcp_SYN.isChecked() << 1) +
                                   int(self.checkBox_tcp_FIN.isChecked() << 0))
                if (win := self.spinBox_tcp_WIN.value()) != 0:
                    tcpPacket.window = win
                # if crc := self.lineEdit_tcp_Checksum.text() != "":
                #     tcpPacket.chksum = crc
                if (urgP := self.spinBox_tcp_Urgent.value()) != 0:
                    tcpPacket.urgptr = urgP
                tcpopti = ""
                if self.checkBox_tcp_Nops.isChecked():
                    tcpopti = tcpopti + 2 * str(0x01)
                if self.checkBox_tcp_Timestamp.isChecked():
                    tcpopti = tcpopti + str(0x08) + str(0x0a) + str(hex(int(time.time())))
                tcpPacket.options = tcpopti

                ipPacket = ipPacket/tcpPacket
            else:
                udpPacket = inet.UDP()

                if (sport := self.spinBox_udp_SRCPort.value()) != 0:
                    udpPacket.sport = sport
                if (dport := self.spinBox_udp_DSTPort.value()) != 0:
                    udpPacket.dport = dport
                if (len := self.spinBox_udp_Length.value()) != 0:
                    udpPacket.len = len

                # for chksum
                pkt = inet.IP() / udpPacket
                pkt = inet.IP(inet.raw(pkt))
                if self.lineEdit_udp_Checksum.text() != "" and pkt[inet.UDP].chksum != self.lineEdit_udp_Checksum.text():
                    udpPacket.chksum = int(self.lineEdit_udp_Checksum.text())
                ipPacket = ipPacket/udpPacket

        frame = frame/ipPacket


        for t in range(times):
            l2.sendp(frame, return_packets=True, verbose=False)
            time.sleep(delay / 1000)

    def showBitChange(self, nState, bitname="", proto=""):
        if nState:
            self.statusBar.showMessage(str(proto) + " " + str(bitname) + " bit set")
        else:
            self.statusBar.showMessage(str(proto) + " " + str(bitname) + " bit unset")

    def getMacAddress(self, ip="0.0.0.0"):
        try:
            mac = l2.getmacbyip(ip)
            if mac == "ff:ff:ff:ff:ff:ff" or mac == "00:00:00:00:00:00":
                # tested only on Mac OS, and not working pretty well with virtual interfaces, like virtualbox interfaces
                return psutil.net_if_addrs()[self.comboInterfacesBox.currentText()][1].address
            else:
                return mac
        except:
            pass

    # Slots:
    def sendBtnClicked(self):
        times = self.timesSpinBox.value()
        delay = self.delaySpinBox.value()
        print("pushed button send with times = ", times, " delay = ", delay)
        self.sendPacket(times, delay)

    def tcpSourcePortChanged(self):
        nValue = self.spinBox_tcp_SRCPort.text()
        self.statusBar.showMessage("TCP SRC port changed to " + str(nValue), 1000)

    def tcpDestinationPortChanged(self):
        nValue = self.spinBox_tcp_DSTPort.text()
        self.statusBar.showMessage("TCP DST port changed to " + str(nValue), 1000)

    def tcpSEQNumChanged(self):
        nValue = self.spinBox_tcp_SEQ.text()
        self.statusBar.showMessage("TCP SEQ changed to " + str(nValue), 1000)

    def tcpACKChanged(self):
        nValue = self.spinBox_tcp_ACK.text()
        self.statusBar.showMessage("TCP ACK changed to " + str(nValue), 1000)

    def tcpDataOffsetChanged(self):
        nValue = self.spinBox_tcp_DataOffset.text()
        self.statusBar.showMessage("TCP Data Offset changed to " + str(nValue), 1000)

    def tcpRes1Changed(self, nState):
        self.showBitChange(nState, "Res1", "TCP")

    def tcpRes2Changed(self, nState):
        self.showBitChange(nState, "Res2", "TCP")

    def tcpRes3Changed(self, nState):
        self.showBitChange(nState, "Res3", "TCP")

    def tcpRes4Changed(self, nState):
        self.showBitChange(nState, "Res4", "TCP")

    def tcpCWRChanged(self, nState):
        self.showBitChange(nState, "CWR", "TCP")

    def tcpECEChanged(self, nState):
        self.showBitChange(nState, "ECE", "TCP")

    def tcpURGChanged(self, nState):
        self.showBitChange(nState, "URG", "TCP")

    def tcpACKChanged(self, nState):
        self.showBitChange(nState, "ACK", "TCP")

    def tcpPSHChanged(self, nState):
        self.showBitChange(nState, "PSH", "TCP")

    def tcpRSTChanged(self, nState):
        self.showBitChange(nState, "RST", "TCP")

    def tcpSYNChanged(self, nState):
        self.showBitChange(nState, "SYN", "TCP")

    def tcpFINChanged(self, nState):
        self.showBitChange(nState, "FIN", "TCP")

    def tcpWINChanged(self):
        nValue = self.spinBox_tcp_WIN.text()
        self.statusBar.showMessage("TCP WIN changed to " + str(nValue), 1000)

    def tcpChecksumChanged(self):
        # TODO: actually change the value
        #       don't think that is important print message, that checksum changed
        pass

    def tcpUrgentChanged(self):
        nValue = self.spinBox_tcp_Urgent.text()
        self.statusBar.showMessage("TCP Urgent changed to " + str(nValue), 1000)

    def tcpOptionsAddNopsChanged(self, nState):
        if nState:
            self.statusBar.showMessage("Added two NOP's to the TCP Packet", 1000)
        else:
            self.statusBar.showMessage("Removed two NOP's from the TCP Packet", 1000)

    def tcpOptionsAddTimestampChanged(self, nState):
        if nState:
            self.statusBar.showMessage("Added timestamp to the TCP Packet", 1000)
        else:
            self.statusBar.showMessage("Removed timestamp from the TCP Packet", 1000)

    def tcpDataChanged(self):
        # nValue = self.plainTextEdit_tcp_Data.toPlainText()
        self.statusBar.showMessage("TCP data changed", 1000)

    def udpSourcePortChanged(self):
        nValue = self.spinBox_udp_SRCPort.text()
        self.statusBar.showMessage("UDP SRC port changed to " + str(nValue), 1000)

    def udpDestinationPortChanged(self):
        nValue = self.spinBox_udp_DSTPort.text()
        self.statusBar.showMessage("UDP DST port changed to " + str(nValue), 1000)

    def udpLengthChanged(self):
        nValue = self.spinBox_udp_Length.text()
        self.statusBar.showMessage("UDP length port changed to " + str(nValue), 1000)

    def udpChecksumChanged(self):
        # TODO: actually change the value
        #       dont think that is important print message, that checksum changed
        pass

    def udpDataChanged(self):
        # nValue = self.plainTextEdit_tcp_Data.toPlainText()
        self.statusBar.showMessage("UDP data changed", 1000)

    def ipv4VersionChanged(self):
        nValue = self.spinBox_ipv4_Version.text()
        self.statusBar.showMessage("IPv4 version changed to " + str(nValue), 1000)

    def ipv4IHLChanged(self):
        nValue = self.spinBox_ipv4_IHL.text()
        self.statusBar.showMessage("IPv4 IHL changed to " + str(nValue), 1000)

    def ipv4DSCPChanged(self):
        # TODO: actually change the value
        #       and deal with icmp -- need to merge DSCP and ECN to ToS
        nValue = self.spinBox_ipv4_DSCP.text()
        self.statusBar.showMessage("IPv4 DSCP changed to " + str(nValue), 1000)

    def ipv4ECNChanged(self):
        nValue = self.spinBox_ipv4_ECN.text()
        self.statusBar.showMessage("IPv4 ECN changed to " + str(nValue), 1000)

    def ipv4TotalLengthChanged(self):
        nValue = self.spinBox_ipv4_TotalLength.text()
        self.statusBar.showMessage("IPv4 total length changed to " + str(nValue), 1000)

    def ipv4IdentificationChanged(self):
        nValue = self.spinBox_ipv4_Identification.text()
        self.statusBar.showMessage("IPv4 identification changed to " + str(nValue), 1000)

    def ipv4ResChanged(self, nState):
        self.showBitChange(nState, "RES", "IPv4")

    def ipv4DFChanged(self, nState):
        self.showBitChange(nState, "DF", "IPv4")

    def ipv4MFChanged(self, nState):
        self.showBitChange(nState, "MF", "IPv4")

    def ipv4FragmentOffsetChanged(self):
        nValue = self.spinBox_ipv4_FragmentOffset.text()
        self.statusBar.showMessage("IPv4 fragment offset changed to " + str(nValue), 1000)

    def ipv4ProtocolChanged(self):
        nValue = self.spinBox_ipv4_Protocol.text()
        self.statusBar.showMessage("IPv4 protocol changed to " + str(nValue), 1000)

    def ipv4ChecksumChanged(self):
        #
        pass

    def ipv4SRCIPChanged(self):
        # Fixme: need to change icmp SCR ip after changing ipv4 SRC ip and other way. If set slot/signal done
        #       other fields, caret will go to the end of line every time when user type one char
        # TODO: regexp value and pass only correct done with try/catch

        ind = self.tab_L3_Widget.currentIndex()
        if ind == 0:
            nValue = self.lineEdit_ipv4_SRCIP.text()
            self.lineEdit_icmp_SRCIP.setText(nValue)
        else:
            nValue = self.lineEdit_icmp_SRCIP.text()
            self.lineEdit_ipv4_SRCIP.setText(nValue)
        self.lineEdit_mac_SRCMAC.setText(self.getMacAddress(nValue))

        self.statusBar.showMessage("IPv4 SRC IP length changed to " + str(nValue), 1000)

    def ipv4DSTIPChanged(self):
        # Fixme: need to change icmp DST ip after changing ipv4 DST ip and other way. If set slot/signal done
        #       other fields, caret will go to the end of line every time when user type one char
        ind = self.tab_L3_Widget.currentIndex()
        if ind == 0:
            nValue = self.lineEdit_ipv4_DSTIP.text()
            self.lineEdit_icmp_DSTIP.setText(nValue)
        else:
            nValue = self.lineEdit_icmp_DSTIP.text()
            self.lineEdit_ipv4_DSTIP.setText(nValue)
        self.lineEdit_mac_DSTMAC.setText(self.getMacAddress(nValue))
        self.statusBar.showMessage("IPv4 DST IP length changed to " + str(nValue), 1000)

    def ipv4OptionsCopiedChanged(self, nState):
        self.showBitChange(nState, "Copied", "IPv4 Options")

    def ipv4OptionsClassChanged(self):
        nValue = self.spinBox_ipv4_options_Class.text()
        self.statusBar.showMessage("IPv4 Option Class changed to " + str(nValue), 1000)

    def ipv4OptionsNumberChanged(self):
        nValue = self.spinBox_ipv4_options_Number.text()
        self.statusBar.showMessage("IPv4 Option Number changed to " + str(nValue), 1000)

    def ipv4OptionsLengthChanged(self):
        nValue = self.spinBox_ipv4_options_Length.text()
        self.statusBar.showMessage("IPv4 Option length changed to " + str(nValue), 1000)

    def ipv4OptionsDataChanged(self):
        pass

    def ipv4DataChanged(self):
        pass

    def icmpTypeChanged(self):
        nValue = self.spinBox_icmp_Type.text()
        self.statusBar.showMessage("ICMP type changed to " + str(nValue), 1000)

    def icmpCodeChanged(self):
        nValue = self.spinBox_icmp_Code.text()
        self.statusBar.showMessage("ICMP code changed to " + str(nValue), 1000)

    def icmpChecksumChanged(self):
        pass

    def icmpDataChanged(self):
        pass

    def macPreambleChanged(self):
        nValue = self.lineEdit_mac_Preamble.text()
        self.statusBar.showMessage("MAC preamble changed to " + str(nValue), 1000)

    def macSFDChanged(self):
        nValue = self.lineEdit_mac_SFD.text()
        self.statusBar.showMessage("MAC SFD changed to " + str(nValue), 1000)

    def macSRCMacChanged(self):
        nValue = self.lineEdit_mac_SRCMAC.text()
        self.statusBar.showMessage("MAC SRC Mac changed to " + str(nValue), 1000)

    def macDSTMacChanged(self):
        nValue = self.lineEdit_mac_DSTMAC.text()
        self.statusBar.showMessage("MAC DST Mac changed to " + str(nValue), 1000)

    def macLengthChanged(self):
        nValue = self.spinBox_mac_Length.text()
        self.statusBar.showMessage("MAC length changed to " + str(nValue), 1000)

    def macChecksumChanged(self):
        pass

    def macDataChanged(self):
        pass


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = PacketSender()
    window.show()
    app.exec_()


if __name__ == '__main__':
    main()

# To get plain text from plain text:
# text = self.plainTextEdit_tcp_Data.toPlainText()
# print(text)
