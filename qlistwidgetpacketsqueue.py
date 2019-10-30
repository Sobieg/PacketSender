from PyQt5 import QtWidgets
import design


class QListWidgetPacketsQueue(QtWidgets.QListWidget, design.Ui_PacketSender):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent

    def myAddItem(self, item):
        super().addItem(item)
