from PyQt6 import QtWidgets
import design


class QListWidgetSavedPackets(QtWidgets.QListWidget, design.Ui_PacketSender):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent



