import ctypes
import json
from ctypes import *
from ctypes.wintypes import *
import psutil
import win32api
import sys
from PySide6 import QtCore, QtWidgets, QtGui

# 定义Windows API函数
import win32process

OpenProcess = windll.kernel32.OpenProcess
ReadProcessMemory = windll.kernel32.ReadProcessMemory
CloseHandle = windll.kernel32.CloseHandle

# 定义访问权限常量
PROCESS_ALL_ACCESS = 0x1F0FFF


class WoLongCheat:
    processHandle = None
    baseAddr = None
    equipment_map = None

    dict_map = [{'name': "武勋", "address": 0X2D6374C}, {'name': "铜钱", "address": 0X2D63748},
                {'name': "真气", "address": 0X2D63740},
                {'name': '锻造材料基质集合', "address": 0x2D3CD40, "offset": 0x8},
                {'name': '道具基质集合', "address": 0x2D3AED0, "offset": 0x8}]

    def init(self):
        pid = self.find_pid('WoLong.exe')
        self.processHandle = win32api.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        modules = win32process.EnumProcessModules(self.processHandle)
        self.baseAddr = modules[0]

    def find_pid(self, process_name):
        for proc in psutil.process_iter():  # 遍历所有运行中的进程
            if process_name in proc.name():  # 检查进程名是否匹配
                pid = proc.pid  # 获取PID
                break  # 跳出循环
        if pid:  # 如果找到了PID
            return pid
        else:  # 如果没有找到PID
            return False

    def get_value_from_addr(self, addr, bytes=4):
        res = win32process.ReadProcessMemory(self.processHandle, addr, bytes)
        res = int.from_bytes(res, byteorder='little')
        res =  res - 16**(2*bytes) if res > 15**(2*bytes) else res
        return res

    def write_value_to_addr(self, addr, value):
        value = 16**(2*4) + value if value < 0 else value
        value = value.to_bytes(4, "little")
        print(addr)
        win32process.WriteProcessMemory(self.processHandle, addr, value)

    def get_value_from_pointer(self, addr, offset):
        real_addr = self.get_pointer_address(addr)
        if real_addr:
            real_addr = real_addr + offset
        else:
            return False
        value = self.get_value_from_addr(real_addr, 4)
        return value

    def get_pointer_address(self, addr):
        real_addr = self.get_value_from_addr(addr, 8)
        if real_addr:
            return real_addr
        else:
            return False

    def show_all_cheat_value(self):
        for item in self.dict_map:
            value = self.get_value_from_addr(item['address'])
            print(f"{item['name']}:{value}")

    def close(self):
        self.processHandle.close()

    def get_basic_dict_map(self):
        return [{'name': "武勋", "address": 0x2D7898C}, {'name': "铜钱", "address": 0x2D78988},
                {'name': "真气", "address": 0x2D78980}]
    def get_equipment_map(self):
        if not self.equipment_map:
            f = open("equipment.json", 'rb')
            data = f.read()
            f.close()
            self.equipment_map = json.loads(data)
        return self.equipment_map
    def get_equipment_name(self,id):
        equipment_map = self.get_equipment_map()
        if equipment_map.get(f"{id}"):
            return equipment_map.get(f"{id}")
        return ""




class MyWidget(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        # QtCore.code
        # QtCore.code.setCodecForLocale(QtCore.QTextCodec.codecForName("UTF-8"))

        self.cheat = WoLongCheat()
        self.cheat.init()
        self.layout = QtWidgets.QVBoxLayout(self)

        self.layout.addLayout(self.get_base_info_layout())
        self.layout.addLayout(self.get_inventory_layout())

    @QtCore.Slot()
    def showMessage(self):
        msgBox = QtWidgets.QMessageBox()
        msgBox.setText("Hello world")
        msgBox.setStandardButtons(QtWidgets.QMessageBox.Ok)
        ret = msgBox.exec()

    def get_base_info_layout(self):
        basic_map = self.cheat.get_basic_dict_map()
        basic_layout = QtWidgets.QVBoxLayout()
        basic_layout.addWidget(QtWidgets.QLabel("基础信息"))
        for item in basic_map:
            tmp_layout = QtWidgets.QHBoxLayout()
            tmp_layout.addWidget(QtWidgets.QLabel(item['name']))
            sp = QtWidgets.QLineEdit()
            value = self.cheat.get_value_from_addr(self.cheat.baseAddr + item['address'])
            sp.setText(f"{value}")
            tmp_layout.addWidget(sp)
            button = QtWidgets.QPushButton('修改')
            button.clicked[bool].connect(
                lambda checked, sp=sp, address=self.cheat.baseAddr + item['address']: self.update_value(sp, address))
            tmp_layout.addWidget(button)
            basic_layout.addLayout(tmp_layout)

        return basic_layout

    def get_inventory_layout(self):
        basic_layout = QtWidgets.QVBoxLayout()
        basic_layout.addWidget(QtWidgets.QLabel("物品栏"))
        num = 250
        table_widget = QtWidgets.QTableWidget(num, 5)
        table_widget.setHorizontalHeaderLabels(["装备key", "装备名","装备数量", "星级", "特殊效果"])
        basic_layout.addWidget(table_widget)
        addr = 0x2D50548
        each_addr_offset = 0x100
        for i in range(0, num):
            equipment_base_addr = self.cheat.get_pointer_address(self.cheat.baseAddr + addr)
            equipment_base_addr = equipment_base_addr - i * each_addr_offset + 0x200*60
            if equipment_base_addr:
                key = self.cheat.get_value_from_addr(equipment_base_addr + 16)
                key_qti = QtWidgets.QTableWidgetItem(f"{key}")
                key_qti.setData(QtCore.Qt.UserRole, equipment_base_addr + 16)
                table_widget.setItem(i, 0, key_qti)
                table_widget.setItem(i, 1, QtWidgets.QTableWidgetItem(f"{self.cheat.get_equipment_name(key)}{equipment_base_addr}"))
                count = self.cheat.get_value_from_addr(equipment_base_addr + 24)
                count_qti = QtWidgets.QTableWidgetItem(f"{count}")
                count_qti.setData(QtCore.Qt.UserRole, equipment_base_addr + 24)
                table_widget.setItem(i, 2, count_qti)
                star = self.cheat.get_value_from_addr(equipment_base_addr + 40)
                star_qti = QtWidgets.QTableWidgetItem(f"{star}")
                star_qti.setData(QtCore.Qt.UserRole, equipment_base_addr + 40)
                table_widget.setItem(i, 3, star_qti)
                special_effect_button = QtWidgets.QPushButton("查看")
                special_effect_button.clicked[bool].connect(
                    lambda checked, equipment_base_addr=equipment_base_addr: self.display_special_effect(
                        equipment_base_addr))
                table_widget.setCellWidget(i, 4, special_effect_button)

        table_widget.itemChanged.connect(self.on_table_item_change)
        return basic_layout

    @QtCore.Slot()
    def update_value(self, sp, address):
        value = sp.text()
        print(value)
        print(address)
        self.cheat.write_value_to_addr(address, int(value))

    @QtCore.Slot()
    def on_table_item_change(self, item: QtWidgets.QTableWidgetItem):
        address = item.data(QtCore.Qt.UserRole)
        address = int(address)
        print(address)
        self.cheat.write_value_to_addr(address, int((item.text())))

    @QtCore.Slot()
    def display_special_effect(self, equipment_base_addr):
        dialog = QtWidgets.QDialog()
        spec_effect_table = QtWidgets.QTableWidget(6, 3)
        spec_effect_table.setHorizontalHeaderLabels(["状态", "特殊效果id", "特殊效果值"])
        for j in range(0, 6):
            status = self.cheat.get_value_from_addr(equipment_base_addr + 52 + j * 20)
            id = self.cheat.get_value_from_addr(equipment_base_addr + 56 + j * 20)
            value = self.cheat.get_value_from_addr(equipment_base_addr + 60 + j * 20)
            status_qti = QtWidgets.QTableWidgetItem(f"{status}")
            status_qti.setData(QtCore.Qt.UserRole, equipment_base_addr + 52 + j * 20)
            spec_effect_table.setItem(j,0,status_qti)
            id_qti = QtWidgets.QTableWidgetItem(f"{id}")
            id_qti.setData(QtCore.Qt.UserRole, equipment_base_addr + 56 + j * 20)
            spec_effect_table.setItem(j,1,id_qti)
            value_qti = QtWidgets.QTableWidgetItem(f"{value}")
            value_qti.setData(QtCore.Qt.UserRole, equipment_base_addr + 60 + j * 20)
            spec_effect_table.setItem(j, 2, value_qti)
        spec_effect_table.itemChanged.connect(self.on_table_item_change)
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(spec_effect_table)
        close_button = QtWidgets.QPushButton("关闭");
        close_button.clicked.connect(dialog.close)
        layout.addWidget(close_button)
        dialog.setLayout(layout)
        dialog.exec()


if __name__ == '__main__':
    # cheat = WoLongCheat()
    # cheat.init()
    # cheat.show_all_cheat_value()
    # cheat.close()

    app = QtWidgets.QApplication([])
    widget = MyWidget()
    widget.resize(600, 500)
    widget.show()
    sys.exit(app.exec())
