#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
from math import ceil
from scapy.all import *
from PyQt5 import QtWidgets
from gui import Ui_mainWindow


# IP(version=self._current_version, ihl=self._current_ihl,
#    tos=self._current_tos, id=self._current_id, flags=self._current_flags, frag=self._current_frag_offset, ttl=self._current_ttl, proto=self._current_proto, chksum=self._current_chksum)/TCP()


# tmp_pkt_1 = Ether()
# tmp_pkt_2 = IP(options=self._current_ip_options)
# tmp_pkt_3 = TCP()
# tmp_pkt_4 = Raw(load=self._current_load)

# tmp_pkt_1 = Ether(raw(tmp_pkt_1))
# tmp_pkt_2 = IP(raw(tmp_pkt_2))
# tmp_pkt_3 = TCP(raw(tmp_pkt_3))
# tmp_pkt_4 = Raw(raw(tmp_pkt_4))

# tmp_pkt = tmp_pkt_1/tmp_pkt_2/tmp_pkt_3/tmp_pkt_4

class MainWindow(QtWidgets.QMainWindow, Ui_mainWindow):
    current_type = "TCP"
    current_packet = None
    current_adapter = None
    current_if_list = None
    packet_list = []
    sending_queue = []

    _current_packet_name = ''

    ###[ Ethernet ]###
    _current_dst_mac = ''
    _current_src_mac = ''
    ##################
    ###[ IP ]#########
    _current_version = 4
    _current_ihl = 5
    _current_tos = 0
    _current_len = 0
    _current_id = 1
    _current_ip_flags = []
    _current_frag_offset = 0
    _current_ttl = 64
    _current_proto = 0
    _current_ip_chksum = 0
    _current_src_ip = ''
    _current_dst_ip = ''
    _current_ip_options = ''
    ##################
    ###[ TCP/UDP ]####
    _current_src_port = 0
    _current_dst_port = 0
    _current_seq = 0
    _current_ack = 0
    _current_data_offset_or_len = 5
    _current_reserved = 0
    _current_flags = ''
    _current_window = 0
    _current_chksum = None
    _current_urgptr = 0
    _current_tcp_options = ''
    ##################
    ###[ DATA ]#######
    _current_load = ''
    ##################

    def __init__(self):
        super(MainWindow, self).__init__()

        # Set up the user interface from Designer.
        self.setupUi(self)

        self.current_packet = Ether()/IP()/TCP()  # TODO: move to function
        self.current_if_list = get_if_list()
        self.LoadNetworkInterfaces()
        self.SetConnections()
        self.show()

    def LoadNetworkInterfaces(self):
        self.adaptersBox.model().item(0).setEnabled(False)
        self.adaptersBox.model().item(0)
        for iface in self.current_if_list:
            self.adaptersBox.addItem(dev_from_pcapname(iface).description)

    def ShowError(self):
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Critical)
        msg.setText('Error')
        msg.setInformativeText('Wrong value!')
        msg.setWindowTitle('Error')
        msg.exec_()
        return

    def SetConnections(self):
        self.adaptersBox.currentIndexChanged.connect(self._AdapterChanged)
        self.packetTypeBox.currentIndexChanged.connect(self._PacketTypeChanged)
        self.srcCheckbox.stateChanged.connect(self._SetSrcMac)
        self.srcIpCheckbox.stateChanged.connect(self._SetSrcIp)
        self.dstCheckbox.stateChanged.connect(self._SetDstMac)
        self.dstIpLineEdit.editingFinished.connect(self._DstIpLineEdited)
        self.nameLineEdit.editingFinished.connect(self._NameLineEdited)
        self.srcVerCheckbox.stateChanged.connect(self._SetVer)
        self.lenIpCheckbox.stateChanged.connect(self._SetLen)
        self.checksumCheckbox.stateChanged.connect(self._SetCheckSum)
        self.srcLineEdit.editingFinished.connect(self._SrcLineEdited)
        self.dstLineEdit.editingFinished.connect(self._DstLineEdited)
        self.srcIpLineEdit.editingFinished.connect(self._SrcIpLineEdited)
        self.verLineEdit.editingFinished.connect(self._VerLineEdited)
        self.lenIpLineEdit.editingFinished.connect(self._LenIpLineEdited)
        self.idLineEdit.editingFinished.connect(self._IdLineEdited)
        self.offsetLineEdit.editingFinished.connect(self._OffsetLineEdited)
        self.checksumIpLineEdit.editingFinished.connect(self._ChecksumIpLineEdited)
        self.ttlLineEdit.editingFinished.connect(self._TttLineEdited)
        self.dscpIpLineEdit.editingFinished.connect(self._DscpIpLineEdited)
        self.optionsIpLineEdit.editingFinished.connect(self._OptionsIpLineEdited)
        self.srcPortLineEdit.editingFinished.connect(self._SrcPortLineEdited)
        self.dstPortLineEdit.editingFinished.connect(self._DstPortLineEdited)
        self.snLineEdit.editingFinished.connect(self._SnLineEdited)
        self.ackLineEdit.editingFinished.connect(self._AckLineEdited)
        self.lenLineEdit.editingFinished.connect(self._LenLineEdited)
        self.checksumLineEdit.editingFinished.connect(self._ChecksumLineEdited)
        self.optionsLineEdit.editingFinished.connect(self._OptionsLineEdited)
        self.windowLineEdit.editingFinished.connect(self._WindowLineEdited)
        self.urgPtrLineEdit.editingFinished.connect(self._UrgPtrLineEdited)
        self.reservedLineEdit.editingFinished.connect(self._ReservedLineEdited)
        self.lenCheckbox.stateChanged.connect(self._SetTcpLen)
        self.checksumHeaderCheckbox.stateChanged.connect(self._SetHeaderChecksum)
        self.windowCheckbox.stateChanged.connect(self._SetWindow)
        self.flag0Checkbox.stateChanged.connect(self._SetZeroFlag)
        self.flagDfCheckbox.stateChanged.connect(self._SetDfFlag)
        self.flagMfCheckbox.stateChanged.connect(self._SetMfFlag)
        self.urgCheckbox.stateChanged.connect(self._SetUrg)
        self.synCheckbox.stateChanged.connect(self._SetSyn)
        self.pshCheckbox.stateChanged.connect(self._SetPsh)
        self.ackCheckbox.stateChanged.connect(self._SetAck)
        self.rstCheckbox.stateChanged.connect(self._SetRst)
        self.finCheckbox.stateChanged.connect(self._SetFin)
        self.dataTextEdit.textChanged.connect(self._SetData)
        self.addToListPushButton.clicked.connect(self._AddCurrentPacketToList)
        self.removeListPushButton.clicked.connect(self._RemovePacketFromList)
        self.addListPushButton.clicked.connect(self._AddPacketToQueue)
        self.removeQueuePushButton.clicked.connect(self._RemovePacketFromQueue)
        self.sendQueuePushButton.clicked.connect(self._SendPacketQueue)

    def _SendPacketQueue(self):
        for packet in self.sending_queue:
            sendp(packet[0], iface=packet[1])
            packet[0].show2()

    def _RemovePacketFromQueue(self):
        current_row = self.queueListWidget.currentRow()
        if current_row == -1:
            return
        self.queueListWidget.takeItem(current_row)
        self.sending_queue.pop(current_row)

    def _AddPacketToQueue(self):
        current_row = self.packetList.currentRow()
        if current_row == -1:
            return
        self.queueListWidget.addItem(self.packetList.item(current_row).text())
        self.sending_queue.append(self.packet_list[current_row])

    def _RemovePacketFromList(self):
        current_row = self.packetList.currentRow()
        if current_row == -1:
            return
        self.packetList.takeItem(current_row)
        self.packet_list.pop(current_row)
        # print(self.packet_list)
    
    def _AddCurrentPacketToList(self):
        try:
            current_load = self._current_load
            tmp_pkt_eth = Ether(dst=self._current_dst_mac,
                                src=self._current_src_mac)
            tmp_pkt_ip = IP(chksum=self._current_ip_chksum, version=self._current_version, tos=self._current_tos, len=self._current_len, id=self._current_id,
                            flags=self._current_ip_flags, frag=self._current_frag_offset, ttl=self._current_ttl, src=self._current_src_ip, dst=self._current_dst_ip, options=self._current_ip_options)
            if self.current_type == 'TCP':
                current_load = self._current_tcp_options + current_load
                tmp_pkt_transp = TCP(chksum=self._current_chksum, sport=self._current_src_port, dport=self._current_dst_port, seq=self._current_seq, ack=self._current_ack,
                                     dataofs=self._current_data_offset_or_len, reserved=self._current_reserved, flags=self._current_flags, window=self._current_window, urgptr=self._current_urgptr)  # This depends on chosen packet type
            elif self.current_type == 'UDP':
                tmp_pkt_transp = UDP(chksum=self._current_chksum, sport=self._current_src_port, dport=self._current_dst_port,
                                     len=self._current_data_offset_or_len)
            elif self.current_type == 'ICMP_req':
                tmp_pkt_transp = ICMP(chksum=self._current_chksum, type='echo-request', code=self._current_src_port,
                                      id=self._current_dst_port, seq=self._current_seq)
            elif self.current_type == 'ICMP_rep':
                tmp_pkt_transp = ICMP(chksum=self._current_chksum, type='echo-reply', code=self._current_src_port,
                                      id=self._current_dst_port, seq=self._current_seq)
            tmp_pkt_raw = Raw(load=current_load)
            tmp_pkt = tmp_pkt_eth/tmp_pkt_ip/tmp_pkt_transp/tmp_pkt_raw
            if self.adaptersBox.currentIndex() == 0:
                raise ValueError('Current adapter is invalid')
            self.packet_list.append((tmp_pkt, self.adaptersBox.currentText()))
            if self.nameLineEdit.text() == '':
                raise ValueError('Current name is invalid')
            self.packetList.addItem(self.nameLineEdit.text())
            # print (self.packet_list)
        except:
            self.ShowError()

        # tmp_pkt = tmp_pkt.__class__(raw(tmp_pkt))  # LOL hacked

    def _SetData(self):
        self._current_load = self.dataTextEdit.toPlainText()
        self._SetLen()
        self._SetHeaderChecksum()
        self._SetCheckSum()

    def _PacketTypeChanged(self):
        if self.packetTypeBox.currentIndex() == 0:
            self.current_type = 'TCP'
            self.windowLineEdit.setEnabled(True)
            self.snLineEdit.setEnabled(True)
            self.ackLineEdit.setEnabled(True)
            self.reservedLineEdit.setEnabled(True)
            self.optionsLineEdit.setEnabled(True)
            self.windowCheckbox.setEnabled(True)
            self.synCheckbox.setEnabled(True)
            self.ackCheckbox.setEnabled(True)
            self.finCheckbox.setEnabled(True)
            self.pshCheckbox.setEnabled(True)
            self.rstCheckbox.setEnabled(True)
            self.urgCheckbox.setEnabled(True)
            self.snLabel.setEnabled(True)
            self.ackLabel.setEnabled(True)
            self.reservedLabel.setEnabled(True)
            self.optionsLabel.setEnabled(True)
            self.lenLineEdit.setEnabled(True)
            self.lenCheckbox.setEnabled(True)
            self.srcPortLabel.setText('SRC PORT:')
            self.dstPortLabel.setText('DST PORT:')
        elif self.packetTypeBox.currentIndex() == 1:
            self.current_type = 'UDP'
            self.windowLineEdit.setEnabled(False)
            self.snLineEdit.setEnabled(False)
            self.ackLineEdit.setEnabled(False)
            self.reservedLineEdit.setEnabled(False)
            self.optionsLineEdit.setEnabled(False)
            self.windowCheckbox.setEnabled(False)
            self.synCheckbox.setEnabled(False)
            self.ackCheckbox.setEnabled(False)
            self.finCheckbox.setEnabled(False)
            self.pshCheckbox.setEnabled(False)
            self.rstCheckbox.setEnabled(False)
            self.urgCheckbox.setEnabled(False)
            self.snLabel.setEnabled(False)
            self.ackLabel.setEnabled(False)
            self.reservedLabel.setEnabled(False)
            self.optionsLabel.setEnabled(False)
            self.lenLineEdit.setEnabled(True)
            self.lenCheckbox.setEnabled(True)
            self.urgCheckbox.setCheckState(False)
            self.srcPortLabel.setText('SRC PORT:')
            self.dstPortLabel.setText('DST PORT:')
        elif self.packetTypeBox.currentIndex() == 2:
            self.current_type = 'ICMP_req'
            self.windowLineEdit.setEnabled(False)
            self.ackLineEdit.setEnabled(False)
            self.reservedLineEdit.setEnabled(False)
            self.optionsLineEdit.setEnabled(False)
            self.windowCheckbox.setEnabled(False)
            self.synCheckbox.setEnabled(False)
            self.ackCheckbox.setEnabled(False)
            self.finCheckbox.setEnabled(False)
            self.pshCheckbox.setEnabled(False)
            self.rstCheckbox.setEnabled(False)
            self.urgCheckbox.setEnabled(False)
            self.ackLabel.setEnabled(False)
            self.reservedLabel.setEnabled(False)
            self.optionsLabel.setEnabled(False)
            self.lenLineEdit.setEnabled(False)
            self.lenCheckbox.setEnabled(False)
            self.urgCheckbox.setCheckState(False)

            # self.srcPortLineEdit.setEnabled(False)
            # self.dstPortLineEdit.setEnabled(False)


            self.srcPortLabel.setText('CODE:')
            self.dstPortLabel.setText('ID:')
        elif self.packetTypeBox.currentIndex() == 3:
            self.current_type = 'ICMP_rep'
            self.windowLineEdit.setEnabled(False)
            self.ackLineEdit.setEnabled(False)
            self.reservedLineEdit.setEnabled(False)
            self.optionsLineEdit.setEnabled(False)
            self.windowCheckbox.setEnabled(False)
            self.synCheckbox.setEnabled(False)
            self.ackCheckbox.setEnabled(False)
            self.finCheckbox.setEnabled(False)
            self.pshCheckbox.setEnabled(False)
            self.rstCheckbox.setEnabled(False)
            self.urgCheckbox.setEnabled(False)
            self.ackLabel.setEnabled(False)
            self.reservedLabel.setEnabled(False)
            self.optionsLabel.setEnabled(False)
            self.lenLineEdit.setEnabled(False)
            self.lenCheckbox.setEnabled(False)
            self.urgCheckbox.setCheckState(False)

            # self.srcPortLineEdit.setEnabled(False)
            # self.dstPortLineEdit.setEnabled(False)


            self.srcPortLabel.setText('CODE:')
            self.dstPortLabel.setText('ID:')
        

    def _SetFin(self):
        if self.finCheckbox.isChecked() is True:
            self._current_flags += 'F'
        else:
            self._current_flags = self._current_flags.replace('F', '')
        self._SetHeaderChecksum()

    def _SetRst(self):
        if self.rstCheckbox.isChecked() is True:
            self._current_flags += 'R'
        else:
            self._current_flags = self._current_flags.replace('R', '')
        self._SetHeaderChecksum()

    def _SetAck(self):
        if self.ackCheckbox.isChecked() is True:
            self._current_flags += 'A'
        else:
            self._current_flags = self._current_flags.replace('A', '')
        self._SetHeaderChecksum()

    def _SetPsh(self):
        if self.pshCheckbox.isChecked() is True:
            self._current_flags += 'P'
        else:
            self._current_flags = self._current_flags.replace('P', '')
        self._SetHeaderChecksum()

    def _SetSyn(self):
        if self.synCheckbox.isChecked() is True:
            self._current_flags += 'S'
        else:
            self._current_flags = self._current_flags.replace('S', '')
        self._SetHeaderChecksum()

    def _SetUrg(self):
        if self.urgCheckbox.isChecked() is True:
            self.urgPtrLineEdit.setEnabled(True)
            self.urgPtrLabel.setEnabled(True)
            self._current_flags += 'U'
        else:
            self.urgPtrLineEdit.setEnabled(False)
            self.urgPtrLabel.setEnabled(False)
            self._current_flags = self._current_flags.replace('U', '')
        self._SetHeaderChecksum()

    def _SetMfFlag(self):
        if self.flagMfCheckbox.isChecked() is True:
            self._current_ip_flags.append('MF')
        else:
            self._current_ip_flags.remove('MF')
        self._SetCheckSum()

    def _SetDfFlag(self):
        if self.flagDfCheckbox.isChecked() is True:
            self._current_ip_flags.append('DF')
        else:
            self._current_ip_flags.remove('DF')
        self._SetCheckSum()

    def _SetZeroFlag(self):
        if self.flag0Checkbox.isChecked() is True:
            self._current_ip_flags.append('evil')
        else:
            self._current_ip_flags.remove('evil')
        self._SetCheckSum()

    def _SetWindow(self):
        if self.windowCheckbox.isChecked() is True:
            self.windowLineEdit.setEnabled(False)
            tmp_pkt_eth = Ether()
            tmp_pkt_ip = IP()
            # This depends on chosen packet type
            tmp_pkt_transp = TCP(dataofs=self._current_data_offset_or_len)
            tmp_pkt_raw = Raw(load=self._current_load)
            tmp_pkt = tmp_pkt_eth/tmp_pkt_ip/tmp_pkt_transp/tmp_pkt_raw
            tmp_pkt = tmp_pkt.__class__(raw(tmp_pkt))  # LOL hacked
            self.windowLineEdit.setText(str(tmp_pkt.window))
            self._current_window = tmp_pkt.window
            self._SetHeaderChecksum()
        else:
            self.windowLineEdit.setEnabled(True)

    def _SetHeaderChecksum(self):
        if self.checksumHeaderCheckbox.isChecked() is True:
            self.checksumLineEdit.setEnabled(False)
            tmp_pkt_eth = Ether()
            tmp_pkt_ip = IP(src=self._current_src_ip, dst=self._current_dst_ip)
            if self.current_type == 'TCP':
                tmp_pkt_transp = TCP(sport=self._current_src_port, dport=self._current_dst_port, seq=self._current_seq, ack=self._current_ack,
                                     dataofs=self._current_data_offset_or_len, reserved=self._current_reserved, flags=self._current_flags, window=self._current_window, urgptr=self._current_urgptr)  # This depends on chosen packet type
            elif self.current_type == 'UDP':
                tmp_pkt_transp = UDP(sport=self._current_src_port, dport=self._current_dst_port,
                                     len=self._current_data_offset_or_len)
            elif self.current_type == 'ICMP_req':
                tmp_pkt_transp = ICMP(type='echo-request', code=self._current_src_port,
                                      id=self._current_dst_port, seq=self._current_seq)
            elif self.current_type == 'ICMP_rep':
                tmp_pkt_transp = ICMP(type='echo-reply', code=self._current_src_port,
                                      id=self._current_dst_port, seq=self._current_seq)
            tmp_pkt_raw = Raw(load=self._current_load)
            tmp_pkt = tmp_pkt_eth/tmp_pkt_ip/tmp_pkt_transp/tmp_pkt_raw
            tmp_pkt = tmp_pkt.__class__(raw(tmp_pkt))  # LOL hacked
            if self.current_type == 'TCP':
                self.checksumLineEdit.setText(hex(tmp_pkt[TCP].chksum))
                self._current_chksum = tmp_pkt[TCP].chksum
            elif self.current_type == 'UDP':
                self.checksumLineEdit.setText(hex(tmp_pkt[UDP].chksum))
                self._current_chksum = tmp_pkt[UDP].chksum
            elif self.current_type == 'ICMP_req':
                self.checksumLineEdit.setText(hex(tmp_pkt[ICMP].chksum))
                self._current_chksum = tmp_pkt[ICMP].chksum
            elif self.current_type == 'ICMP_rep':
                self.checksumLineEdit.setText(hex(tmp_pkt[ICMP].chksum))
                self._current_chksum = tmp_pkt[ICMP].chksum
        else:
            self.checksumLineEdit.setEnabled(True)

    def _SetTcpLen(self):
        if self.lenCheckbox.isChecked() is True:
            self.lenLineEdit.setEnabled(False)
            additional_offset = ceil((len(self._current_tcp_options) * 8) / 32)
            final_offset = 5 + additional_offset
            if final_offset > 15:
                final_offset = 15
            self.lenLineEdit.setText(str(final_offset))
            self._current_data_offset_or_len = final_offset
            self._SetHeaderChecksum()
        else:
            self.lenLineEdit.setEnabled(True)

    def _ReservedLineEdited(self):
        try:
            self._current_reserved = int(self.reservedLineEdit.text())
            self._SetHeaderChecksum()
        except:
            self.ShowError()

    def _UrgPtrLineEdited(self):
        try:
            self._current_urgptr = int(self.urgPtrLineEdit.text())
            self._SetHeaderChecksum()
        except:
            self.ShowError()

    def _WindowLineEdited(self):
        try:
            self._current_window = int(self.windowLineEdit.text())
            self._SetHeaderChecksum()
        except:
            self.ShowError()
    
    def _OptionsLineEdited(self):
        self._current_tcp_options = self.optionsLineEdit.text()
        # self._current_load = self._current_tcp_options + self._current_load  - this is in when packed saving
        self._SetHeaderChecksum()
        self._SetTcpLen()

            def _ChecksumLineEdited(self):
            try:
                self._current_chksum = int(self.checksumLineEdit.text(), 0)
            except:
                self.ShowError()

        def _LenLineEdited(self):
            try:
                self._current_data_offset_or_len = int(self.lenLineEdit.text())
                self._SetHeaderChecksum()
            except:
            self.ShowError()

    def _AckLineEdited(self):
        try:
            self._current_ack = int(self.ackLineEdit.text())
            self._SetHeaderChecksum()
        except:
            self.ShowError()

    def _SnLineEdited(self):
        try:
            self._current_seq = int(self.snLineEdit.text())
            self._SetHeaderChecksum()
        except:
            self.ShowError()

    def _DstPortLineEdited(self):
        try:
            self._current_dst_port = int(self.dstPortLineEdit.text())
            self._SetHeaderChecksum()
        except:
            self.ShowError()

    def _SrcPortLineEdited(self):
        try:
            self._current_src_port = int(self.srcPortLineEdit.text())
            self._SetHeaderChecksum()
        except:
            self.ShowError()

    def _DscpIpLineEdited(self):
        try:
            self._current_tos = int(self.dscpIpLineEdit.text())
            self._SetCheckSum()
        except:
            self.ShowError()

    def _OptionsIpLineEdited(self):
        self._current_ip_options = self.optionsIpLineEdit.text()
        self._SetCheckSum()

    def _TttLineEdited(self):
        try:
            self._current_ttl = int(self.ttlLineEdit.text())
            self._SetCheckSum()
        except:
            self.ShowError()

    def _ChecksumIpLineEdited(self):
        try:
            self._current_ip_chksum = int(self.checksumIpLineEdit)
        except:
            self.ShowError()

    def _OffsetLineEdited(self):
        try:
            self._current_frag_offset = int(self.offsetLineEdit.text())
            self._SetCheckSum()
        except:
            self.ShowError()

    def _IdLineEdited(self):
        try:
            self._current_id = int(self.idLineEdit.text())
            self._SetCheckSum()
        except:
            self.ShowError()

    def _LenIpLineEdited(self):
        try:
            self._current_len = int(self.lenIpLineEdit.text())
            self._SetCheckSum()
        except:
            self.ShowError()

    def _VerLineEdited(self):
        try:
            self._current_version = int(self.verLineEdit.text())
            self._SetCheckSum()
        except:
            self.ShowError()
            
    def _SrcIpLineEdited(self):
        self._current_src_ip = self.srcIpLineEdit.text()
        self._SetCheckSum()

    def _DstLineEdited(self):
        self._current_dst_mac = self.dstLineEdit.text()

    def _SrcLineEdited(self):
        self._current_src_mac = self.srcLineEdit.text()

    def _NameLineEdited(self):
        self._current_packet_name = self.nameLineEdit.text()

    def _SetLen(self):
        if self.lenIpCheckbox.isChecked() is True:
            self.lenIpLineEdit.setEnabled(False)
            tmp_pkt_eth = Ether()
            tmp_pkt_ip = IP(options=self._current_ip_options)
            if self.current_type == 'TCP':
                tmp_pkt_transp = TCP()  # This depends on chosen packet type
            elif self.current_type == 'UDP':
                tmp_pkt_transp = UDP()
            elif self.current_type == 'ICMP_req':
                tmp_pkt_transp = ICMP()
            elif self.current_type == 'ICMP_rep':
                tmp_pkt_transp = ICMP()
            tmp_pkt_raw = Raw(load=self._current_load)
            tmp_pkt = tmp_pkt_eth/tmp_pkt_ip/tmp_pkt_transp/tmp_pkt_raw
            tmp_pkt = tmp_pkt.__class__(raw(tmp_pkt))  # LOL hacked
            self.lenIpLineEdit.setText(str(tmp_pkt.len))
            self._current_len = tmp_pkt.len
            self._SetCheckSum()
        else:
            self.lenIpLineEdit.setEnabled(True)

    def _SetVer(self):
        if self.srcVerCheckbox.isChecked() is True:
            self.verLineEdit.setEnabled(False)
            self.verLineEdit.setText('4')
            self._current_version = 4
            self._SetCheckSum()
        else:
            self.verLineEdit.setEnabled(True)

    def _SetSrcMac(self):
        if self.srcCheckbox.isChecked() is True:
            self.srcLineEdit.setEnabled(False)
            if self.adaptersBox.currentIndex() == 0:
                return
            current_mac = dev_from_pcapname(self.current_if_list[self.adaptersBox.currentIndex() - 1]).mac.upper()
            self.srcLineEdit.setText(current_mac)
            self._current_src_mac = current_mac
        else:
            self.srcLineEdit.setEnabled(True)

    def _SetSrcIp(self):
        if self.srcIpCheckbox.isChecked() is True:
            self.srcIpLineEdit.setEnabled(False)
            if self.adaptersBox.currentIndex() == 0:
                return
            current_ip = dev_from_pcapname(
                self.current_if_list[self.adaptersBox.currentIndex() - 1]).ip
            self.srcIpLineEdit.setText(current_ip)
            self._current_src_ip = current_ip
            self._SetCheckSum()
        else:
            self.srcIpLineEdit.setEnabled(True)

    def _SetDstMac(self):
        if self.dstCheckbox.isChecked() is True:
            self.dstLineEdit.setEnabled(False)
            if self.dstIpLineEdit.text() == '':
                self.dstLineEdit.clear()
                return
            current_ip = self.dstIpLineEdit.text()
            tmp_pkt = Ether()/IP(dst=current_ip)
            self.dstLineEdit.setText(tmp_pkt.dst.upper())
            self._current_dst_mac = tmp_pkt.dst
        else:
            self.dstLineEdit.setEnabled(True)

    def _SetCheckSum(self):
        if self.checksumCheckbox.isChecked() is True:
            self.checksumIpLineEdit.setEnabled(False)
            tmp_pkt_eth = Ether()
            tmp_pkt_ip = IP(version=self._current_version, tos=self._current_tos, len=self._current_len, id=self._current_id,
                            flags=self._current_ip_flags, frag=self._current_frag_offset, ttl=self._current_ttl, src=self._current_src_ip, dst=self._current_dst_ip, options=self._current_ip_options)
            if self.current_type == 'TCP':
                tmp_pkt_transp = TCP()  # This depends on chosen packet type
            if self.current_type == 'UDP':
                tmp_pkt_transp = UDP()
            elif self.current_type == 'ICMP_req':
                tmp_pkt_transp = ICMP()
            elif self.current_type == 'ICMP_rep':
                tmp_pkt_transp = ICMP()
            tmp_pkt_raw = Raw(load=self._current_load)
            tmp_pkt = tmp_pkt_eth/tmp_pkt_ip/tmp_pkt_transp/tmp_pkt_raw
            tmp_pkt = tmp_pkt.__class__(raw(tmp_pkt))  # LOL hacked
            # tmp_pkt.show()
            self.checksumIpLineEdit.setText(hex(tmp_pkt.chksum))
            self._current_ip_chksum = tmp_pkt.chksum
        else:
            self.checksumIpLineEdit.setEnabled(True)

    def _DstIpLineEdited(self):
        self._SetDstMac()
        self._current_dst_ip = self.dstIpLineEdit.text()
        self._SetCheckSum()

    def _AdapterChanged(self):
        self._SetSrcMac()
        self._SetSrcIp()

        # self.current_adapter = self.adaptersBox.currentData

        # # Make some local modifications.
        # self.colorDepthCombo.addItem("2 colors (1 bit per pixel)")

        # # Connect up the buttons.
        # self.okButton.clicked.connect(self.accept)
        # self.cancelButton.clicked.connect(self.reject)


if __name__ == '__main__':

    # app = QtWidgets.QApplication(sys.argv)

    # w = QtWidgets.QWidget()
    # w.resize(250, 150)
    # w.move(300, 300)
    # w.setWindowTitle('Simple')
    # w.show()

    # sys.exit(app.exec_())
    # scapy.all.ls(TCP)
    # packet = IP(dst="4.5.6.7",src="1.2.3.4")/TCP(dport=80, flags="S")
    # packet.show()
    app = QtWidgets.QApplication(sys.argv)
    # window = QtWidgets.QMainWindow()
    # ui = Ui_mainWindow()
    # ui.setupUi(window)

    # window.show()

    ui = MainWindow()

    sys.exit(app.exec_())
