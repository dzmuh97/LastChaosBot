import psutil
import struct
import time
import sys
import os

import win32api
import win32gui
import win32con
import win32process
import win32security

import ntsecuritycon
import threading

from ctypes import *
from ctypes.wintypes import *

from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import QBasicTimer

from ui import Ui_mainWindow

import _pickle as PKL
import logging
import math

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(name)s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='log.txt',
                    filemode='w')
LOG = logging.getLogger('BOT')
LOG.addHandler(logging.StreamHandler(sys.stdout))

class MODULEINFO(Structure):
    _fields_ = [
        ("lpBaseOfDll",     LPVOID),    # remote pointer
        ("SizeOfImage",     DWORD),
        ("EntryPoint",      LPVOID),    # remote pointer
]

PROCESS_NAME = 'Nksp.exe'
LOADED_MODULES = []

VK_CODE = {
    'tab': 0x09,
    'enter': 0x0D,
    'shift': 0x10,
    'ctrl': 0x11,
    'alt': 0x12,
    '0': 0x30,
    '1': 0x31,
    '2': 0x32,
    '3': 0x33,
    '4': 0x34,
    '5': 0x35,
    '6': 0x36,
    '7': 0x37,
    '8': 0x38,
    '9': 0x39,
    '{F1}': 0x70,
    '{F2}': 0x71,
    '{F3}': 0x72,
    '{F4}': 0x73,
    '{F5}': 0x74,
    '{F6}': 0x75,
    '{F7}': 0x76,
    '{F8}': 0x77,
    '{F9}': 0x78,
    '{F10}': 0x79,
    '{F11}': 0x7A,
    '{F12}': 0x7B,
    'a': 0x41,
    'b': 0x42,
    'c': 0x43,
    'd': 0x44,
    'e': 0x45,
    'f': 0x46,
    'g': 0x47,
    'h': 0x48,
    'i': 0x49,
    'j': 0x4A,
    'k': 0x4B,
    'l': 0x4C,
    'm': 0x4D,
    'n': 0x4E,
    'o': 0x4F,
    'p': 0x50,
    'q': 0x51,
    'r': 0x52,
    's': 0x53,
    't': 0x54,
    'u': 0x55,
    'v': 0x56,
    'w': 0x57,
    'x': 0x58,
    'y': 0x59,
    'z': 0x5A,
}

OFFSETS = {
    'addresses': [
        {
            'name': 'cur_health',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A6BBD8, 0x15818]
         },
        {
            'name': 'cur_mana',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A6BBD8, 0x1581C]
         },
        {
            'name': 'max_health',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A6BBD8, 0x1583C]
        },
        {
            'name': 'max_mana',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A6BBD8, 0x15838]
        },
        {
            'name': 'current_ou',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A6BBD8, 0x15860]
        },
        {
            'name': 'current_exp',
            'base_addr': 0,
            'length': 8,
            'type': '<q',
            'offsets': ['Engine.dll', 0x00A6BBD8, 0x15870]
        },
        {
            'name': 'need_exp',
            'base_addr': 0,
            'length': 8,
            'type': '<q',
            'offsets': ['Engine.dll', 0x00A6BBD8, 0x15878]
        },
        {
            'name': 'current_lvl',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A6BBD8, 0x15814]
        },
        {
            'name': 'X',
            'base_addr': 0,
            'length': 4,
            'type': '<f',
            'offsets': ['EntitiesMP.dll', 0x0030A3F0, 0x58]
        },
        {
            'name': 'Z',
            'base_addr': 0,
            'length': 4,
            'type': '<f',
            'offsets': ['EntitiesMP.dll', 0x0030A3F0, 0x5C]
        },
        {
            'name': 'Y',
            'base_addr': 0,
            'length': 4,
            'type': '<f',
            'offsets': ['EntitiesMP.dll', 0x0030A3F0, 0x60]
        },
        {
            'name': 'player_speed',
            'base_addr': 0,
            'length': 4,
            'type': '<f',
            'offsets': ['EntitiesMP.dll', 0x0030A3F0, 0xDE4]
        },
        {
            'name': 'player_aspeed',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['EntitiesMP.dll', 0x0030A3F0, 0xDD8]
        },
        {
            'name': 'player_arange',
            'base_addr': 0,
            'length': 4,
            'type': '<f',
            'offsets': ['EntitiesMP.dll', 0x0030A3F0, 0xDE0]
        },
#################################################################
        {
            'name': 'mob_class',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A5EDB8, 0x5c]
        },
        {
            'name': 'mob_lvl',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets':  ['Engine.dll', 0x00A5EDB8, 0x44]
         },
        {
            'name': 'mob_baseaddr',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A5EDB8, 0x48]
        },
        {
            'name': 'mob_max_hp',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A5EDB8, 0x48, 0x384]
        },
        {
            'name': 'mob_current_hp',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A5EDB8, 0x48, 0x388]
        },
        {
            'name': 'mob_x',
            'base_addr': 0,
            'length': 4,
            'type': '<f',
            'offsets': ['Engine.dll', 0x00A5EDB8, 0x48, 0x58]
        },
        {
            'name': 'mob_z',
            'base_addr': 0,
            'length': 4,
            'type': '<f',
            'offsets': ['Engine.dll', 0x00A5EDB8, 0x48, 0x5C]
        },
        {
            'name': 'mob_y',
            'base_addr': 0,
            'length': 4,
            'type': '<f',
            'offsets': ['Engine.dll', 0x00A5EDB8, 0x48, 0x60]
        },
###########################################################
        {
            'name': 'drop_count',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A5EDA8, 0x5C]
         },
        {
            'name': 'players_count',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A5EDA8, 0xC]
        },
        {
            'name': 'ai_count',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A5EDA8, 0x1C]
        },
        {
            'name': 'ai_base',
            'base_addr': 0,
            'length': 4,
            'type': '<i',
            'offsets': ['Engine.dll', 0x00A6DBF0, 0x7C, 0x0]
        },
        ]
    }

_user32 = ctypes.WinDLL("user32")

k32 = windll.kernel32
k32.OpenProcess.argtypes = DWORD, BOOL, DWORD
k32.OpenProcess.restype = HANDLE

psapi = windll.psapi
psapi.GetModuleInformation.argtypes = HANDLE, HMODULE, POINTER(MODULEINFO), DWORD
psapi.GetModuleInformation.restype = BOOL


class Bot(QtWidgets.QMainWindow):
    def __init__(self, pid):
        super().__init__()

        self.data_status_map = {
            'cur_health': 'HP_CUR',
            'cur_mana': 'MP_CUR',
            'max_health': 'HP_MAX',
            'max_mana': 'MP_MAX',
            'current_ou': 'OU_LABEL',
            'current_exp': 'EXP_LABEL',
            'current_lvl': 'LVL_LABEL',
            'X': 'PLAYER_X',
            'Z': 'PLAYER_Z',
            'Y': 'PLAYER_Y',
            'mob_class': 'MOB_ID',
            'mob_lvl': 'MOB_LVL',
            'mob_max_hp': 'MOB_HP_MAX',
            'mob_current_hp': 'MOB_HP_CUR',
            'drop_count': 'NEAR_ITEMS',
            'players_count': 'NEAR_PLAYERS',
            'ai_count': 'NEAR_AI',
        }

        self.status = ['EXP_LABEL', 'EXP_PER_HOUR', 'EXP_PERCENT',
                       'HP_BAR', 'HP_CUR', 'HP_MAX', 'LVL_LABEL',
                       'MP_BAR', 'MP_CUR', 'MP_MAX', 'OU_LABEL',
                       'OU_PER_HOUR', 'MOB_HP_BAR', 'MOB_HP_CUR', 'MOB_HP_MAX',
                       'MOB_ID', 'MOB_LVL', 'MOB_TO_PLAYER_LEN', 'MOB_TO_CENTER_LEN',
                       'PLAYER_X', 'PLAYER_Y', 'PLAYER_Z',
                       'NEAR_AI', 'NEAR_ITEMS', 'NEAR_PLAYERS']

        self.config = ['HEALTH_POITION_TIMEOUT', 'HEALTH_POITION_PERCENT',
                       'JUMP_OFFSET',
                       'MANA_POITION_TIMEOUT', 'MANA_POITION_PERCENT',
                       'MAX_DISTANCE', 'MAX_MOB_DISTANCE', 'MOB_TIMEOUT',
                       'NEED_LOOT', 'NEAR_PLAYERS_WORK', 'NEAR_PLAYERS_RUN',
                       'LOOT_KEY', 'ATTACK_KEY', 'HP_KEY', 'MP_KEY', 'RUN_KEY',
                       'OTHER_ACTIVATE', 'MOB_START_LVL', 'MOB_END_LVL', 'MOB_CRITICAL_LVL',
                       'USE_RADAR']

        self.ui = Ui_mainWindow()
        self.ui.setupUi(self)

        self.ui.START_BUTTON.clicked.connect(self.run)
        self.ui.STOP_BUTTON.clicked.connect(self.stop)
        self.ui.READY_BUTTON.clicked.connect(self.init_timer)
        self.ui.CH_UPDATE.clicked.connect(self.cheat_update_status)
        self.ui.CH_SET.clicked.connect(self.cheat_set_config)
        self.ui.SAFE_CONFIG.clicked.connect(self.safe_config)
        self.ui.LOAD_CONFIG.clicked.connect(self.load_config)

        self.ui.CHEATS_X_P.clicked.connect(lambda: self.__tp(self.ui.CHEATS_X_P))
        self.ui.CHEATS_X_M.clicked.connect(lambda: self.__tp(self.ui.CHEATS_X_M))
        self.ui.CHEATS_Y_P.clicked.connect(lambda: self.__tp(self.ui.CHEATS_Y_P))
        self.ui.CHEATS_Y_M.clicked.connect(lambda: self.__tp(self.ui.CHEATS_Y_M))
        self.ui.CHEATS_Z_P.clicked.connect(lambda: self.__tp(self.ui.CHEATS_Z_P))
        self.ui.CHEATS_Z_M.clicked.connect(lambda: self.__tp(self.ui.CHEATS_Z_M))

        self.ui.STOP_BUTTON.setEnabled(False)
        self.ui.START_BUTTON.setEnabled(False)

        for q in range(10):
            self.ui.LOOT_KEY.addItem('%d' % q)
            self.ui.ATTACK_KEY.addItem('%d' % q)
            self.ui.HP_KEY.addItem('%d' % q)
            self.ui.MP_KEY.addItem('%d' % q)
            self.ui.RUN_KEY.addItem('%d' % q)

        for q in range(1, 13):
            self.ui.LOOT_KEY.addItem('{F%d}' % q)
            self.ui.ATTACK_KEY.addItem('{F%d}' % q)
            self.ui.HP_KEY.addItem('{F%d}' % q)
            self.ui.MP_KEY.addItem('{F%d}' % q)
            self.ui.RUN_KEY.addItem('{F%d}' % q)

        self.ui.LOOT_KEY.setCurrentIndex(2)
        self.ui.ATTACK_KEY.setCurrentIndex(1)
        self.ui.HP_KEY.setCurrentIndex(3)
        self.ui.MP_KEY.setCurrentIndex(4)
        self.ui.RUN_KEY.setCurrentIndex(5)

        self.ui.tableWidget.setColumnCount(5)
        self.ui.tableWidget.setRowCount(10)
        self.ui.tableWidget.setHorizontalHeaderLabels(('ВКЛ', 'Скилл?', 'Кнопка', 'Ожидание', 'Время каста'))

        def centeredWidget(item):
            widget = QtWidgets.QWidget()
            layout = QtWidgets.QHBoxLayout(widget)

            layout.addWidget(item)
            layout.setAlignment(QtCore.Qt.AlignCenter)
            layout.setContentsMargins(0, 0, 0, 0)

            widget.setLayout(layout)
            return widget

        self.ui.tableWidget.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        for row in range(10):
            act = QtWidgets.QCheckBox()
            skill = QtWidgets.QCheckBox()
            combo = QtWidgets.QComboBox()
            wait = QtWidgets.QSpinBox()
            cast = QtWidgets.QSpinBox()

            for q in range(1, 13):
                combo.addItem('{F%d}' % q)

            for q in range(10):
                combo.addItem('%d' % q)

            wait.setMaximum(9999)
            cast.setMaximum(9999)

            self.ui.tableWidget.setCellWidget(row, 0, centeredWidget(act))
            self.ui.tableWidget.setCellWidget(row, 1, centeredWidget(skill))
            self.ui.tableWidget.setCellWidget(row, 2, combo)
            self.ui.tableWidget.setCellWidget(row, 3, wait)
            self.ui.tableWidget.setCellWidget(row, 4, cast)
        self.ui.tableWidget.resizeColumnsToContents()

        self.timer = QBasicTimer()
        self.running = threading.Event()
        self.localtime = int(time.time())
        self.collected_exp = 0
        self.collected_ou = 0

        self.ccords = {'x': 0, 'y': 0, 'z': 0}
        self.skills = {}

        self.game = GData(pid)

        self.th = threading.Thread(target=self.work)
        self.th.daemon = True

        self.cheating = False

        self.init_status()
        self.update_config()

    def cheat_update_status(self):
        self.game.update_data()

        run_speed = self.game.get_data('player_speed')
        aspeed = self.game.get_data('player_aspeed')
        arange = self.game.get_data('player_arange')

        if not all([run_speed, aspeed, arange]):
            return

        self.ui.RUN_SPEED_SL.setValue(int(run_speed))
        self.ui.ATTACK_SP_SL.setValue(aspeed)
        self.ui.ATTACK_DL_SL.setValue(int(arange))

    def cheat_set_config(self):
        if self.cheating:
            self.ui.CH_SET.setText('Установить')
        else:
            self.ui.CH_SET.setText('Отменить')

        self.cheating = not self.cheating

    def __cheat_set(self):
        self.game.update_data()

        run_speed = self.ui.RUN_SPEED_SL.value()
        aspeed = self.ui.ATTACK_SP_SL.value()
        arange = self.ui.ATTACK_DL_SL.value()

        self.game.set_data('player_speed', run_speed)
        self.game.set_data('player_aspeed', aspeed)
        self.game.set_data('player_arange', arange)

    def __tp(self, btn):
        if btn == self.ui.CHEATS_X_P:
            self.game.set_data('X', float(self.PLAYER_X) + 1)
        if btn == self.ui.CHEATS_X_M:
            self.game.set_data('X', float(self.PLAYER_X) - 1)
        if btn == self.ui.CHEATS_Y_P:
            self.game.set_data('Y', float(self.PLAYER_Y) + 1)
        if btn == self.ui.CHEATS_Y_M:
            self.game.set_data('Y', float(self.PLAYER_Y) - 1)
        if btn == self.ui.CHEATS_Z_P:
            self.game.set_data('Z', float(self.PLAYER_Z) + 1)
        if btn == self.ui.CHEATS_Z_M:
            self.game.set_data('Z', float(self.PLAYER_Z) - 1)

    def update_status(self):
        for status in self.status:
            box = getattr(self.ui, status)

            if isinstance(box, QtWidgets.QLabel):
                box.setText(str(getattr(self, status)))
            if isinstance(box, QtWidgets.QProgressBar):
                box.setValue(getattr(self, status))
            if isinstance(box, QtWidgets.QCheckBox):
                box.setChecked(getattr(self, status))

    def update_config(self):
        for status in self.config:
            obj = getattr(self.ui, status)
            if isinstance(obj, QtWidgets.QSpinBox):
                setattr(self, status, obj.value())
            if isinstance(obj, QtWidgets.QCheckBox):
                setattr(self, status, obj.isChecked())
            if isinstance(obj, QtWidgets.QComboBox):
                setattr(self, status, obj.currentText())

        self.skills = {'bufs': [], 'skills': []}
        for row in range(10):
            act = self.ui.tableWidget.cellWidget(row, 0).children()[-1]
            skill = self.ui.tableWidget.cellWidget(row, 1).children()[-1]
            key = self.ui.tableWidget.cellWidget(row, 2).currentText()
            wait = self.ui.tableWidget.cellWidget(row, 3).value()
            cast = self.ui.tableWidget.cellWidget(row, 4).value()

            if act.isChecked():
                if skill.isChecked():
                    base = 'skills'
                else:
                    base = 'bufs'
                self.skills[base].append({'key': key, 'wait': wait, 'cast': cast})

    def safe_config(self):
        cfg = {}

        for status in self.config:
            obj = getattr(self.ui, status)
            if isinstance(obj, QtWidgets.QSpinBox):
                cfg.update({status: obj.value()})
            if isinstance(obj, QtWidgets.QCheckBox):
                cfg.update({status: obj.isChecked()})
            if isinstance(obj, QtWidgets.QComboBox):
                cfg.update({status: obj.currentText()})

        skills = []
        for row in range(10):
            act = self.ui.tableWidget.cellWidget(row, 0).children()[-1].isChecked()
            skill = self.ui.tableWidget.cellWidget(row, 1).children()[-1].isChecked()
            key = self.ui.tableWidget.cellWidget(row, 2).currentText()
            wait = self.ui.tableWidget.cellWidget(row, 3).value()
            cast = self.ui.tableWidget.cellWidget(row, 4).value()

            skills.append([act, skill, key, wait, cast])

        cfg.update({'skills': skills})

        file = open('config.bin', 'wb')
        PKL.dump(cfg, file)
        file.close()

    def load_config(self):
        if not os.path.exists('config.bin'):
            LOG.error('Config file not found!')
            return

        file = open('config.bin', 'rb')
        cfg = PKL.load(file)
        file.close()

        for status, data in cfg.items():
            if status == 'skills':
                continue

            obj = getattr(self.ui, status)
            if isinstance(obj, QtWidgets.QSpinBox):
                obj.setValue(data)
            if isinstance(obj, QtWidgets.QCheckBox):
                obj.setChecked(data)
            if isinstance(obj, QtWidgets.QComboBox):
                obj.setCurrentText(data)

        for i,row in enumerate(cfg['skills']):
            act, skill, key, wait, cast = row
            self.ui.tableWidget.cellWidget(i, 0).children()[-1].setChecked(act)
            self.ui.tableWidget.cellWidget(i, 1).children()[-1].setChecked(skill)
            self.ui.tableWidget.cellWidget(i, 2).setCurrentText(key)
            self.ui.tableWidget.cellWidget(i, 3).setValue(wait)
            self.ui.tableWidget.cellWidget(i, 4).setValue(cast)

    def init_status(self):
        for status in self.status:
            setattr(self, status, 0)

    def timerEvent(self, e):
        self.game.update_data()

        int2dot = lambda x: '{:,}'.format(int(x)).replace(',', '.')
        dot2int = lambda x: int(str(x).replace('.', ''))
        path_len = lambda x1, x2, y1, y2: math.sqrt( (x1 - x2)**2 + (y1 - y2)**2)

        old_exp = dot2int(self.EXP_LABEL)
        old_ou = dot2int(self.OU_LABEL)

        for datan, status in self.data_status_map.items():
            data = self.game.get_data(datan)
            if data is None:
                data = 0

            setattr(self, status, data)

        if self.HP_MAX == 0:
            self.HP_BAR = 0
        else:
            self.HP_BAR = int((self.HP_CUR / self.HP_MAX) * 100)

        if self.MP_MAX == 0:
            self.MP_BAR = 0
        else:
            self.MP_BAR = int((self.MP_CUR / self.MP_MAX) * 100)

        if self.MOB_HP_MAX == 0:
            self.MOB_HP_BAR = 0
        else:
            self.MOB_HP_BAR = int((self.MOB_HP_CUR / self.MOB_HP_MAX) * 100)

        player_need_exp = self.game.get_data('need_exp')
        if player_need_exp is None or player_need_exp == 0:
            self.EXP_PERCENT = 0
        else:
            self.EXP_PERCENT = int((self.EXP_LABEL / player_need_exp) * 100)

        self.EXP_PER_HOUR = 0
        self.OU_PER_HOUR = 0

        ntime = int(time.time())
        time_elapsed = ntime - self.localtime
        if time_elapsed > 0:
            ou = self.OU_LABEL // 10000

            if old_exp > 0:
                exp_laps = self.EXP_LABEL - old_exp
                if exp_laps > 0:
                    self.collected_exp += exp_laps

            if old_ou > 0:
                ou_laps = ou - old_ou
                if ou_laps > 0:
                    self.collected_ou += ou_laps

            self.EXP_PER_HOUR = (self.collected_exp / time_elapsed) * 3600
            self.OU_PER_HOUR = (self.collected_ou / time_elapsed) * 3600

        self.EXP_PER_HOUR = int2dot(self.EXP_PER_HOUR)
        self.OU_PER_HOUR = int2dot(self.OU_PER_HOUR)
        self.EXP_LABEL = int2dot(self.EXP_LABEL)
        self.OU_LABEL = int2dot(self.OU_LABEL // 10000)

        self.MP_CUR = int2dot(self.MP_CUR)
        self.MP_MAX = int2dot(self.MP_MAX)
        self.HP_CUR = int2dot(self.HP_CUR)
        self.HP_MAX = int2dot(self.HP_MAX)
        self.MOB_HP_CUR = int2dot(self.MOB_HP_CUR)
        self.MOB_HP_MAX = int2dot(self.MOB_HP_MAX)

        self.EXP_PERCENT = '%d%%' % self.EXP_PERCENT

        selected_mob_x = self.game.get_data('mob_x')
        selected_mob_y = self.game.get_data('mob_y')
        if selected_mob_x and selected_mob_y:
            self.MOB_TO_PLAYER_LEN = int(path_len(self.PLAYER_X, selected_mob_x, self.PLAYER_Y, selected_mob_y))
            if self.ccords['x'] and self.ccords['y']:
                self.MOB_TO_CENTER_LEN = int(path_len(self.ccords['x'], selected_mob_x, self.ccords['y'], selected_mob_y))
        else:
            self.MOB_TO_CENTER_LEN = 0
            self.MOB_TO_PLAYER_LEN = 0

        self.PLAYER_X = '{:.2f}'.format(self.PLAYER_X)
        self.PLAYER_Y = '{:.2f}'.format(self.PLAYER_Y)
        self.PLAYER_Z = '{:.2f}'.format(self.PLAYER_Z)

        if self.cheating:
            self.__cheat_set()

        self.update_status()
        self.update_config()

    def init_timer(self):
        self.ui.READY_BUTTON.setEnabled(False)
        self.ui.START_BUTTON.setEnabled(True)
        self.ui.STOP_BUTTON.setEnabled(False)
        self.game.update_hwnd()
        self.timer.start(100, self)
        self.th.start()

    def stop(self):
        self.ui.STOP_BUTTON.setEnabled(False)
        self.ui.START_BUTTON.setEnabled(True)
        self.running.clear()

    def run(self):
        self.ui.START_BUTTON.setEnabled(False)
        self.ui.STOP_BUTTON.setEnabled(True)
        self.localtime = int(time.time())
        self.collected_exp = 0
        self.collected_ou = 0
        self.running.set()

    def work(self):
        self.game.update_data()

        path_len = lambda x1, x2, y1, y2: math.sqrt((x1 - x2) ** 2 + (y1 - y2) ** 2)
        dot2int = lambda x: int(str(x).replace('.', ''))

        tfar_counter = 0
        used_buffs = {}
        used_mobs = []

        while True:
            if not self.running.is_set():
                self.running.wait()
                self.ccords['x'] = float(self.PLAYER_X)
                self.ccords['y'] = float(self.PLAYER_Y)
                self.ccords['z'] = float(self.PLAYER_Z) + .1
                used_buffs = {}
                LOG.info('Starting...')

            if self.NEAR_PLAYERS > 0:
                LOG.info('\t| Players detected!')

                if self.NEAR_PLAYERS_WORK or self.NEAR_PLAYERS_RUN:
                    LOG.info('\t| Stop working..')

                    if self.NEAR_PLAYERS_RUN:
                        LOG.info('\t| We don\'t retreat - we are going in a different direction. Douglas MacArthur.')
                        self.game.send_key(VK_CODE[self.RUN_KEY])

                    self.ui.STOP_BUTTON.setEnabled(False)
                    self.ui.START_BUTTON.setEnabled(True)
                    self.running.clear()
                    continue

                LOG.info('\t| Pathetic humans are not a hindrance to me..')

            x = float(self.PLAYER_X)
            y = float(self.PLAYER_Y)
            z = float(self.PLAYER_Z)

            if path_len(self.ccords['x'], x, self.ccords['y'], y) > self.MAX_DISTANCE or tfar_counter > 10:
                self.go_home(self.ccords['x'], self.ccords['y'], self.ccords['z'], x, y, z)
                tfar_counter = 0

            if self.NEAR_AI == 0:
                LOG.info('\t| I think I killed everyone..')
                tfar_counter += 5
                time.sleep(1)
                continue

            if self.USE_RADAR:
                nearest = self.find_nearest_mobs()
                lens = []
                for base, mx, my, mz in nearest:
                    ln = path_len(mx, x, my, y)
                    lens.append((ln, base))

                sorted_mobs = sorted(lens, key=lambda x: x[0])
                for min_mob in sorted_mobs:
                    min_mob_len, min_mob_addr = min_mob
                    iip = 0

                    LOG.info('Searching target %x with distance %d' % (min_mob_addr, min_mob_len))

                    if min_mob_addr in used_mobs:
                        continue

                    if min_mob_len > self.MAX_MOB_DISTANCE:
                        continue

                    if self.OTHER_ACTIVATE:
                        if self.MOB_LVL > self.MOB_CRITICAL_LVL:
                            LOG.info('\t| Mob LVL incorrect')
                            continue

                        if (self.MOB_LVL > self.MOB_END_LVL) or (self.MOB_LVL < self.MOB_START_LVL):
                            LOG.info('\t| Mob LVL incorrect')
                            continue

                    addr = self.game.get_data('mob_baseaddr')
                    while (addr != min_mob_addr) and (iip < self.NEAR_AI):
                        self.game.send_key(VK_CODE['tab'])
                        time.sleep(.51)
                        addr = self.game.get_data('mob_baseaddr')
                        LOG.info('\t| Selected addr: %x' % addr)
                        iip += 1

                    if iip == self.NEAR_AI:
                        continue

                    used_mobs.append(min_mob_addr)
                    if len(used_mobs) > 3:
                        used_mobs.pop(0)
                    break
            else:
                LOG.info('Searching target..')
                self.game.send_key(VK_CODE['tab'])
                time.sleep(.51)

            if self.MOB_LVL == 0:
                LOG.info('\t| Cant select mob..')
                ############################
                # from ahk import ActionChain
                # ac = ActionChain()
                # ac.click(1241, 824)
                # ac.click(1064, 932)
                # ac.click(1241, 824)
                # ac.click(1030, 932)
                # ac.click(732, 454)
                # ac.perform()
                # time.sleep(.3)
                #############################
                tfar_counter += 1
                continue

            if self.OTHER_ACTIVATE:
                if self.MOB_LVL > self.MOB_CRITICAL_LVL:
                    LOG.info('\t| Too high mob detected. Run away!')
                    self.game.send_key(self.RUN_KEY)
                    self.ui.STOP_BUTTON.setEnabled(False)
                    self.ui.START_BUTTON.setEnabled(True)
                    self.running.clear()
                    continue

                if (self.MOB_LVL > self.MOB_END_LVL) or (self.MOB_LVL < self.MOB_START_LVL):
                    LOG.info('\t| Mob LVL incorrect')
                    continue

            mob_coord_x = self.game.get_data('mob_x')
            mob_coord_y = self.game.get_data('mob_y')

            if path_len(mob_coord_x, x, mob_coord_y, y) > self.MAX_MOB_DISTANCE:
                LOG.info('\t| Target too far')
                tfar_counter += 1
                continue

            LOG.info('\t| Start attack')

            counter = 0
            battle_time = 0
            mana_poition_counter = self.MANA_POITION_TIMEOUT
            health_poition_counter = self.HEALTH_POITION_TIMEOUT

            mob_old_health = dot2int(self.MOB_HP_CUR)
            while True:
                health = dot2int(self.HP_CUR)
                max_health = dot2int(self.HP_MAX)

                mana = dot2int(self.MP_CUR)
                max_mana = dot2int(self.MP_MAX)

                mob_lvl = self.MOB_LVL
                mob_class = self.MOB_ID

                mob_health = dot2int(self.MOB_HP_CUR)
                mob_max_health = dot2int(self.MOB_HP_MAX)

                LOG.info('\t| Mob health: %d / %d, Player status: HP: %d / %d, MP: %d / %d' %
                      (mob_health, mob_max_health, health, max_health, mana, max_mana))

                if not self.running.is_set():
                    break

                if battle_time == 0:
                    for buf in self.skills['bufs']:
                        ctime = int(time.time())
                        if ctime - used_buffs.get(buf['key'], 0) < buf['wait']:
                            continue
                        LOG.info('\t| Use buff: %s' % buf['key'])
                        self.game.send_key(VK_CODE[buf['key']])
                        used_buffs.update({buf['key']: ctime})
                        time.sleep(buf['cast'])

                for skill in self.skills['skills']:
                    if battle_time % skill['wait'] == 0:
                        LOG.info('\t| Use skill: %s' % skill['key'])
                        self.game.send_key(VK_CODE[skill['key']])
                        time.sleep(skill['cast'])

                if mob_class > 2**30:
                    LOG.info('\t| Player Detected!!!!')
                    return

                if mob_lvl == 0:
                    LOG.info('\t| Mob died!\n')
                    break

                if health < max_health * (self.HEALTH_POITION_PERCENT / 100):
                    if health_poition_counter >= self.HEALTH_POITION_TIMEOUT:
                        LOG.info('\t| Use health regen')
                        self.game.send_key(VK_CODE[self.HP_KEY])
                        health_poition_counter = 0

                if mana < max_mana * (self.MANA_POITION_PERCENT / 100):
                    if mana_poition_counter >= self.MANA_POITION_TIMEOUT:
                        LOG.info('\t| Use mana regen')
                        self.game.send_key(VK_CODE[self.MP_KEY])
                        mana_poition_counter = 0

                if counter > self.MOB_TIMEOUT:
                    if mob_health >= mob_old_health:
                        LOG.info('\t| Mob health diff: %d -> %d' % (mob_old_health, mob_health))
                        LOG.info('\t| Timeout!')
                        tfar_counter += 5
                        break
                    mob_old_health = self.game.get_data('mob_current_hp')
                    counter = 0

                self.game.send_key(VK_CODE[self.ATTACK_KEY])
                time.sleep(1)

                mana_poition_counter += 1
                health_poition_counter += 1
                battle_time += 1
                counter += 1

            if self.NEED_LOOT:
                time.sleep(1)
                self.loot_ground()

    def go_home(self, start_x, start_y, start_z, x, y, z):
        while x != start_x or y != start_y or z != start_z:
            rx = start_x - x
            ry = start_y - y
            rz = start_z - z

            nx = min(self.JUMP_OFFSET, abs(rx))
            ny = min(self.JUMP_OFFSET, abs(ry))
            nz = min(self.JUMP_OFFSET, abs(rz))

            x = x + nx if rx > 0 else x - nx
            y = y + ny if ry > 0 else y - ny
            z = z + nz if rz > 0 else z - nz

            LOG.info('\t| Jump to %s %s %s' % (x, y, x))

            self.game.set_data('X', x)
            self.game.set_data('Y', y)
            self.game.set_data('Z', z)

            self.game.send_key(VK_CODE['w'], .05)
            time.sleep(.3)

    def loot_ground(self):
        LOG.info('\t| Searching loot items...')
        for i in range(1, self.NEAR_ITEMS + 1):
            LOG.info('\t| Loot item %d / %d' % (i, self.NEAR_ITEMS))
            self.game.send_key(VK_CODE[self.LOOT_KEY])
            time.sleep(1.5)
            continue

    def find_nearest_mobs(self):
        mobs = []
        found = 0
        offset = 0

        base = self.game.get_base_addr('ai_base')
        while found < self.NEAR_AI:
            address = base + offset
            data = self.game.get_addr_data('<i', address, 4)

            h = self.game.get_addr_data('<i', data + 0x384, 4)
            hm = self.game.get_addr_data('<i', data + 0x388, 4)
            l = self.game.get_addr_data('<i', data + 0x38C, 4)
            i = self.game.get_addr_data('<i', data + 0x394, 4)

            x = self.game.get_addr_data('<f', data + 0x58, 4)
            z = self.game.get_addr_data('<f', data + 0x5C, 4)
            y = self.game.get_addr_data('<f', data + 0x60, 4)

            offset += 4
            if h and hm and l and i and x and y and z:
                if l > 185 or l < 1:
                    continue

                if i > 65535 or i < 1:
                    continue

                if x <= 0 or y <= 0 or z <= 0:
                    continue

                mobs.append([data, x, y, z])
                found += 1
        return mobs


class GData:
    def __init__(self, pid):
        self.pid = pid
        self.hwnd = -1
        self.game_data = OFFSETS.copy()
        self.proc = self.__init_process()

    def update_data(self):
        for block in self.game_data['addresses']:
            offsets = block['offsets']
            address = get_adress_with_offsets(self.proc, offsets)
            block['base_addr'] = address

    def __get_params(self, name):
        DTYPE = None
        addr = 0
        ln = 0

        for block in self.game_data['addresses']:
            if block['name'] == name:
                addr = block['base_addr']
                ln = block['length']
                DTYPE = block['type']
                break

        return DTYPE, addr, ln

    def get_base_addr(self, name):
        items = filter(lambda x: x['name'] == name, OFFSETS['addresses'])
        return list(items)[0]['base_addr']

    def get_addr_data(self, dtype, addr, ln):
        data = read_data(self.proc, ln, addr)
        if data is None:
            return None

        value = struct.unpack(dtype, data)[0]
        return value

    def get_data(self, name):
        DTYPE, addr, ln = self.__get_params(name)

        if addr == 0:
            return None

        data = read_data(self.proc, ln, addr)
        if data is None:
            return None

        #print(DTYPE, ln, addr, data)

        value = struct.unpack(DTYPE, data)[0]
        return value

    def set_data(self, name, value):
        DTYPE, addr, ln = self.__get_params(name)

        if addr == 0:
            return None

        data = write_data(self.proc, ln, addr, DTYPE, value)
        return data

    def send_key(self, key, wait=.1):
        lparam = win32api.MAKELONG(0, _user32.MapVirtualKeyA(key, 0))
        win32api.PostMessage(self.hwnd, win32con.WM_KEYDOWN, key, lparam)
        time.sleep(wait)
        win32api.PostMessage(self.hwnd, win32con.WM_KEYUP, key, lparam | 0xC0000000)

    def update_hwnd(self):
        print('Wait to load game GUI..')

        def cb(hw, lst):
            _, fpid = win32process.GetWindowThreadProcessId(hw)
            if fpid == self.pid:
                lst.append(hw)

        wins = []
        while len(wins) == 0:
            win32gui.EnumWindows(cb, wins)
            time.sleep(1)

        self.hwnd = wins[0]
        print('Game HWND:', self.hwnd)

    def __init_process(self):
        proc = k32.OpenProcess(0x0400 | 0x1000 | 0x0008 | 0x0010 | 0x0020, 0, self.pid)

        print('Try to get modules..')
        while True:
            try:
                get_loaded_modules(proc)
                break
            except Exception as e:
                print(type(e), e)
            time.sleep(.1)

        return proc


def find_procs_by_name(name):
    for p in psutil.process_iter():
        name_, pid = "", 0
        try:
            name_ = p.name()
            pid = p.pid
        except (psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except psutil.NoSuchProcess:
            continue
        if name == name_:
            return pid
    return None


def read_data(process, len, addr):
    buf = create_string_buffer(len)
    s = c_size_t()

    if k32.ReadProcessMemory(process, addr, buf, len, byref(s)):
        return buf.raw
    else:
        return None


def write_data(process, len, addr, vtype, value):
    val = struct.pack(vtype, value)
    buf = c_char_p(val)
    s = c_size_t()

    if k32.WriteProcessMemory(process, addr, buf, len, byref(s)):
        return True
    else:
        return False


def get_loaded_modules(proc):
    global LOADED_MODULES, OFFSETS

    dlls = win32process.EnumProcessModulesEx(proc, 0x03)
    for dll in dlls:
        data = MODULEINFO()
        psapi.GetModuleInformation(proc, dll, data, sizeof(data))
        name = win32process.GetModuleFileNameEx(proc, dll)

        print('%s -> 0x%x' % (name, data.lpBaseOfDll))

        LOADED_MODULES.append([name, data.lpBaseOfDll])

    print('Loaded modules:', len(LOADED_MODULES))


def get_adress_with_offsets(proc, offset_list):
    global LOADED_MODULES

    base_module = offset_list[0]
    oindex = 1
    addr = 0

    for fname, offset in LOADED_MODULES:
        if base_module in fname:
            addr = offset
            break

    if addr == 0:
        print('Base offset = 0, try to remap modules')
        LOADED_MODULES = []
        get_loaded_modules(proc)
        return 0

    #print('Base module offset: %s->%x' % (base_module, addr))

    while True:
        offset = offset_list[oindex]
        #print('%x %x %x' % (addr, offset, addr + offset), end=' ')
        if oindex == len(offset_list) - 1:
            #print('\n')
            return addr + offset

        addr = read_data(proc, 4, addr + offset)
        if addr is None:
            #print('\n')
            return 0

        addr = int.from_bytes(addr, 'little')
        if addr == 0:
            #print('\n')
            return 0

        oindex += 1

        #print('-> %x' % addr)


def get_extra_privs():
    th = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
    privs = win32security.GetTokenInformation(th, ntsecuritycon.TokenPrivileges)
    newprivs = []

    for privtuple in privs:
        if privtuple[0] == win32security.LookupPrivilegeValue(None, "SeBackupPrivilege")\
            or privtuple[0] == win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")\
            or privtuple[0] == win32security.LookupPrivilegeValue(None, "SeSecurityPrivilege"):
            print("Added privilege " + str(privtuple[0]))
            # privtuple[1] = 2 # tuples are immutable.  WHY?!
            newprivs.append((privtuple[0], 2))  # SE_PRIVILEGE_ENABLED
        else:
            newprivs.append((privtuple[0], privtuple[1]))
    privs = tuple(newprivs)
    str(win32security.AdjustTokenPrivileges(th, False, privs))


def main():
    get_extra_privs()

    print('Wait to start Nksp.exe process..')
    pid = find_procs_by_name(PROCESS_NAME)
    while pid is None:
        pid = find_procs_by_name(PROCESS_NAME)
        time.sleep(.1)

    print('Game PID:', pid)

    time.sleep(1)
    app = QtWidgets.QApplication([])
    application = Bot(pid)
    application.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
