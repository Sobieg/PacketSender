from PyQt6 import QtWidgets
import design


class PSIpProtoSpinBox(QtWidgets.QSpinBox, design.Ui_PacketSender):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent

    def setProto(self, state):
        if state == 0:
            super().setValue(6)
        elif state == 1:
            super().setValue(17)

