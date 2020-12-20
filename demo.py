from sys import platform
import requests
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QApplication, QMainWindow, QLineEdit, QComboBox, QFrame, QFileDialog
import sys
import os
import SparkFHE
import pathlib

from requests.api import head
from spiritlab.example.Config import Config
import time
import threading
import uuid
import urllib.request


class MyWindow(QMainWindow):
    def __init__(self):
        super(MyWindow, self).__init__()
        self.privateKey = None
        self.setGeometry(400, 200, 670, 360)
        self.setFixedSize(670, 400)
        self.setWindowTitle("SparkFHE UI")
        self.resultURL = ""
        self.secKeyPath = ""
        self.pubKeyPath = ""
        self.uid = uuid.uuid4().hex
        self.baseURL = "http://128.105.145.177:8002/"
        self.pwd = pathlib.Path(__file__).resolve().parent
        self.initUI()

    def initUI(self):
        self.encryptUI()
        self.inputUI()
        self.resultUI()
        print(self.pwd)

    def encryptUI(self):
        self.lblSelEnc = QtWidgets.QLabel(self)
        self.lblSelEnc.setText("Select Encryption Schemes:")
        self.lblSelEnc.move(120, 19)
        self.lblSelEnc.adjustSize()

        self.selKeys = QComboBox(self)
        self.selKeys.setFixedWidth(130)
        self.selKeys.addItems(["HElib - BGV",
                               "HElib - CKKS", "SEAL - BFV", "SEAL - CKKS"])
        self.selKeys.move(290, 15)

        self.btnGenKey = QtWidgets.QPushButton(self)
        self.btnGenKey.setText("Generate Key")
        self.btnGenKey.setFixedWidth(120)
        self.btnGenKey.clicked.connect(self.generateKey)
        self.btnGenKey.move(420, 15)

        self.btnImportKey = QtWidgets.QPushButton(self)
        self.btnImportKey.setText("Import Key")
        self.btnImportKey.setFixedWidth(435)
        # self.btnImportKey.setFixedHeight(20)
        self.btnImportKey.clicked.connect(self.importKey)
        self.btnImportKey.move(110, 45)
        self.btnImportKey.setEnabled(False)

        self.lblKeyLocation = QtWidgets.QLabel(self)
        self.lblKeyLocation.setText("yoyoingf asda")
        self.lblKeyLocation.move(280, 75)
        self.lblKeyLocation.adjustSize()
        self.lblKeyLocation.hide()

        self.lblGenKeys = QtWidgets.QLabel(self)
        self.lblGenKeys.setText("Generating Keys...")
        self.lblGenKeys.move(280, 75)
        self.lblGenKeys.adjustSize()
        self.lblGenKeys.hide()

        self.l1 = QtWidgets.QLabel(self)
        self.l1.setText(
            "_"*150)
        self.l1.move(0, 90)
        self.l1.adjustSize()

    def inputUI(self):
        self.lblInp1 = QtWidgets.QLabel(self)
        self.lblInp1.setText("Input number(s):")
        self.lblInp1.move(90, 105)

        self.input1 = QLineEdit(self)
        self.input1.move(90, 130)

        self.cb = QComboBox(self)
        self.cb.addItems(["Add", "Multiply"])
        self.cb.move(220, 130)

        self.lblInp2 = QtWidgets.QLabel(self)
        self.lblInp2.setText("Input number(s):")
        self.lblInp2.move(340, 105)

        self.input2 = QLineEdit(self)
        self.input2.move(340, 130)

        self.btnEncrypt = QtWidgets.QPushButton(self)
        self.btnEncrypt.setText("Encrypt")
        self.btnEncrypt.clicked.connect(self.encryptInputs)
        self.btnEncrypt.move(480, 130)
        self.btnEncrypt.setEnabled(False)

        self.lblCypherLoc = QtWidgets.QLabel(self)
        self.lblCypherLoc.setText("")
        self.lblCypherLoc.move(280, 170)
        self.lblCypherLoc.adjustSize()

        self.btnComputeKey = QtWidgets.QPushButton(self)
        self.btnComputeKey.setText("Send and Compute")
        self.btnComputeKey.setFixedWidth(435)
        # self.btnComputeKey.setFixedHeight(20)
        self.btnComputeKey.clicked.connect(self.computeRes)
        self.btnComputeKey.move(110, 190)
        self.btnComputeKey.setEnabled(False)

        self.lblUploading = QtWidgets.QLabel(self)
        self.lblUploading.setText("Uploading...")
        self.lblUploading.move(295, 215)
        self.lblUploading.adjustSize()
        self.lblUploading.hide()

        self.l2 = QtWidgets.QLabel(self)
        self.l2.setText(
            "_"*150)
        self.l2.move(0, 220)
        self.l2.adjustSize()

    def resultUI(self):
        self.lblStatus = QtWidgets.QLabel(self)
        self.lblStatus.setText("")
        self.lblStatus.move(295, 240)
        self.lblStatus.adjustSize()

        self.btnDecryptRes = QtWidgets.QPushButton(self)
        self.btnDecryptRes.setText("Fetch and Decrypt")
        self.btnDecryptRes.setFixedWidth(435)
        self.btnDecryptRes.clicked.connect(self.decryptFile)
        self.btnDecryptRes.move(110, 260)
        self.btnDecryptRes.setEnabled(False)

        self.lblResult = QtWidgets.QLabel(self)
        self.lblResult.setText("Result:")
        self.lblResult.move(300, 285)

        self.inpResult = QLineEdit(self)
        self.inpResult.move(110, 310)
        self.inpResult.setFixedWidth(435)

######################## Event Handlers ########################

    def genKeys(self):
        library, scheme = [x.strip().upper()
                           for x in self.selKeys.currentText().split('-')]
        SparkFHE.init(library, scheme)

        self.secKeyPath = self.dir_path + "/my_secret_key.txt"
        self.pubKeyPath = self.dir_path + "/my_public_key.txt"

        SparkFHE.getInstance().generate_key_pair(
            Config.get_default_crypto_params_file(library),
            self.pubKeyPath,
            self.secKeyPath
        )
        self.btnEncrypt.setEnabled(True)

    def generateKey(self):
        self.lblGenKeys.show()
        self.dir_path = QFileDialog.getExistingDirectory(
            self, "Where to save keys?", str(self.pwd))
        if self.dir_path:
            t1 = threading.Thread(target=self.genKeys)
            t1.start()
            t1.join()
            self.lblKeyLocation.move(120, 75)
            self.lblKeyLocation.setText(
                "Key location: " + self.dir_path)
            self.update(self.lblKeyLocation)
            self.lblKeyLocation.show()
        self.lblGenKeys.hide()

    def generateKeyx(self):
        self.dir_path = QFileDialog.getExistingDirectory(
            self, "Where to save keys?", str(self.pwd))
        if self.dir_path:
            self.lblKeyLocation.setText("Generating key.....")
            self.update(self.lblKeyLocation)
            # await self.setLabel()
            library, scheme = [x.strip().upper()
                               for x in self.selKeys.currentText().split('-')]
            SparkFHE.init(library, scheme)

            SparkFHE.getInstance().generate_key_pair(
                Config.get_default_crypto_params_file(library),
                self.dir_path + "/my_public_key.txt",
                self.dir_path + "/my_secret_key.txt"
            )

            self.lblKeyLocation.move(120, 75)
            self.lblKeyLocation.setText(
                "Key location: " + self.dir_path)
            self.update(self.lblKeyLocation)
            self.btnEncrypt.setEnabled(True)

    def encryptInputs(self):
        inp1 = self.input1.text()
        inp2 = self.input2.text()
        ptxt1 = SparkFHE.Plaintext(inp1)
        ptxt2 = SparkFHE.Plaintext(inp2)
        ctxt1 = SparkFHE.getInstance().encrypt(ptxt1)
        ctxt2 = SparkFHE.getInstance().encrypt(ptxt2)
        save1 = open(self.dir_path + '/inp1.txt', 'w')
        save1.write(ctxt1.toString())
        save1.close()
        save2 = open(self.dir_path + '/inp2.txt', 'w')
        save2.write(ctxt2.toString())
        save2.close()

        self.lblCypherLoc.setText(
            "Ciphertexts saved at : " + self.dir_path)
        self.lblCypherLoc.move(100, 170)
        self.lblCypherLoc.adjustSize()
        self.btnComputeKey.setEnabled(True)

        # res = SparkFHE.getInstance().fhe_add(ctxt1, ctxt2)
        # ptxt = SparkFHE.getInstance().decrypt(res, True)
        # print("Ans is :", ptxt.toString())
        # res = SparkFHE.getInstance().do_FHE_basic_op(ctxt1, ctxt2, SparkFHE.FHE_ADD)

    def importKey(self):
        filename = QFileDialog.getOpenFileName()
        self.privateKey = filename
        self.lblKeyLocation.move(20, 75)
        self.lblKeyLocation.setText(
            "Key location: " + filename)
        self.update(self.lblKeyLocation)
        self.btnEncrypt.setEnabled(True)

    def computeRes(self):
        # self.lblUploading.show()
        # t2 = threading.Thread(target=self.lblUploading.show)
        # t2.start()
        # t2.join()
        operand = self.cb.currentText()
        library, scheme = [x.strip().upper()
                           for x in self.selKeys.currentText().split('-')]

        files = {'pk': open(self.dir_path+'/my_public_key.txt', 'rb'),
                 'sk': open(self.dir_path+'/my_secret_key.txt', 'rb'),
                 'ctxt1': open(self.dir_path+'/inp1.txt', 'rb'),
                 'ctxt2': open(self.dir_path+'/inp2.txt', 'rb'), }

        payload = {'operand': operand, 'library': library,
                   'scheme': scheme, 'uid': self.uid}

        url = self.baseURL+'compute'
        # url = 'http://192.168.86.44:5002/compute'
        # url = 'http://127.0.0.1:5000/test'
        # r = requests.get(url)

        r = requests.post(url, params=payload, files=files)

        print('got the DRIVER ID as ::: ', r.text)
        self.driverId = r.text.rstrip()
        # self.driverId = "driver-20201120131320-0166"

        # time.sleep(3)
        # self.checkStatus(r.text)

        result = open(self.dir_path+'/result.txt', 'w')
        # result.write(r.text)
        result.close()

        self.lblStatus.setText("Files have been uploaded to cluster!")
        # self.lblStatus.setText(
        #     "Result at: " + self.dir_path+'/result.txt')
        self.lblStatus.move(220, 240)
        self.lblStatus.adjustSize()
        self.btnDecryptRes.setEnabled(True)

    def checkStatus(self, driverId, status=""):
        # TASK_RUNNING
        # http://hp026.utah.cloudlab.us:5051/files/download?path=/var/lib/mesos/slaves/13da8831-a83e-4394-ad90-57641191f591-S1/frameworks/13da8831-a83e-4394-ad90-57641191f591-0000/executors/driver-20201120110548-0148/runs/630ae481-29d9-4258-ab3f-d98855a7b5e7/stdout
        print("INSIDE CHECK STATUS!", not status, driverId)
        url = self.baseURL+'fetch?uid='+driverId+'&id='+self.uid
        print("URL IS: ", url)
        status = requests.get(
            url, headers={'Cache-Control': 'no-cache', "Pragma": "no-cache"})
        print("AFTER CALL:::", status, status.text)
        if not status or status.text in ['TASK_RUNNING', 'NOT_FOUND']:
            print("CHECKING STATUS AGAIN!!")
            threading.Timer(15, self.checkStatus, [driverId]).start()
        else:
            self.resultURL = status.text

    def decryptFile(self):
        headers = {"Cache-Control": "no-cache", "Pragma": "no-cache"}
        url = self.baseURL+'fetch'
        status = requests.get(
            url, params={'uid': self.driverId, 'id': self.uid})
        print("URL::", url, self.driverId)
        print("RES:::", status.text)
        if status.text in ['TASK_RUNNING', 'NOT_FOUND']:
            print("still computing...")
            self.inpResult.setText(
                "Still computing... Please retry after some time..")
        elif status.text == "TASK_FAILED":
            self.inpResult.setText("Something went wrong, Task Failed.")
        else:
            self.inpResult.setText("")
            local_fname = self.dir_path+'/result.txt'
            filename, headers = urllib.request.urlretrieve(
                status.text, local_fname)
            ciphertxt = open(self.dir_path+'/result.txt', 'r').read()
            restxt = ciphertxt.split("txt...")[1]
            plaintxt = SparkFHE.getInstance().decrypt(restxt, True)
            self.inpResult.setText(plaintxt)

        self.inpResult.setAlignment(QtCore.Qt.AlignCenter)

    def decryptFileOLD(self):
        filename = QFileDialog.getOpenFileName()
        ciphertxt = open(filename[0], 'r').read()
        plaintxt = SparkFHE.getInstance().decrypt(ciphertxt, True)
        self.inpResult.setText(plaintxt)
        self.inpResult.setAlignment(QtCore.Qt.AlignCenter)

    def update(self, label):
        label.adjustSize()


def window():
    app = QApplication(sys.argv)
    win = MyWindow()
    win.show()
    sys.exit(app.exec_())


window()
