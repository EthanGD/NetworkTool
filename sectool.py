# -*- coding: utf-8 -*-

#
# Created: Wed Nov 04 12:26:17 2015
#      by: Topper
#
# WARNING! All changes made in this file will be lost!
import sys
import socket
import time
import re
#import win32api
import random
import struct
import threading
import os
import urllib
import base64
import md5
import binascii
from IPy import IP
from PyQt4 import QtCore, QtGui,Qt
from PyQt4.QtGui import QPalette,QColor
reload(sys)
sys.setdefaultencoding( "utf-8" )
#采用UTF8编码方式发送数据流


G_Code=u"""
#!/bin/env python
#coding=utf8
#Autor  topper

import sys
import socket
import time

def h2bin(x):
    return x.replace(' ', '').replace('\\n', '').decode('hex')
    
txt=$txt$

data = h2bin(txt)

def main():
    ip=raw_input("TargetIP:")
    num=int(raw_input("SendCount:"))
    port=80
    for i in range(num):
        soc=socket.socket()
        soc.settimeout(2)
        try:
            soc.connect((ip,port))
            soc.send(data)
            print "Testing...\\tNum:% d" %(i+1)
        except:
            print "\\nSorry! Device Crashed !!!"
            return
        time.sleep(0.1)
    print "\\nCongratulations! Device Not Found Bug..."

if __name__=='__main__':
    main()
    print "\\nTest Over!!!"
    raw_input("Enter Key By Quit")
"""





#定义全局控制变量--------------------------------
G_Singal=0      #控制信号:(0:停止 1:运行 2:暂停)
G_Ori_Data=["N",""]   #保存原始数据包(第一个用来标识N,Y，第二个用来存储)
G_Light=0             #闪烁
G_ScanFlag=0          #控制扫描状态 
G_Raw=0               #数据量返回报文形式 0--明文  1--16进制流
mutex = threading.Lock()#定义全局锁


try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)



#多线程
class workthread(QtCore.QThread):
    ret_num = QtCore.pyqtSignal(int)            #返回当前运行的次数
    ret_status = QtCore.pyqtSignal(int)         #返回当前结果 1 状态良好  2 设备异常  3发送完成  
    ret_res = QtCore.pyqtSignal(str)            #返回当前信息
    ret_ScanRes = QtCore.pyqtSignal(str,str)    #返回扫描信息
    
    def __init__(self,parent=None):
        super(workthread,self).__init__(parent)



    def GetIpScan(self,vIpList,vPortList,vTimeOut):
        self.IpList=vIpList
        self.PortList=vPortList
        self.TimeOut=vTimeOut
        self.flag="ScanIp"
        
        
    def SetBigFile(self,ip,port,BigFileName,num,stime,auth="none"):
        self.ip=ip
        self.port=port
        self.num=num
        self.stime=stime 
        self.BigFileName=BigFileName
        if auth=="none":
            self.flag="SendBigFile_NAuth"
        
        
        
    def sender(self,ip,port,data,num,stime,auth="none",user="",pwd=""):
        self.ip=ip
        self.port=port
        self.num=num
        self.stime=stime   
        self.data=data
        self.user=user
        self.pwd=pwd
        self.flag=auth
        self.start()
    
    def run(self):
        if self.flag=="none":                   #发送正常TCP报文
            self.send_data("Normal") 
        elif self.flag=="UDP-Recv":             #发送UDP接收报文
            self.send_data_udp("Recv")
        elif self.flag=="UDP-Send":             #发送UDP不接收报文
            self.send_data_udp("Send") 
        elif self.flag=="UDP-Multicast":        #发送组播报文
            self.send_data_udp("Multicast")             
        elif self.flag=="TCP-Random":           #发送TCP随机数据
            self.send_data("Random")                        
        elif self.flag=="ScanIp":               #端口扫描
            self.ScanPort() 
        elif self.flag=="SendBigFile_NAuth":    #发送文件
            self.SendBigFile()
         
         
    
    def ScanPort(self):
        global G_ScanFlag
        threads=[]
        if G_ScanFlag==1:   #已运行，不重复扫描
            return
        elif G_ScanFlag==0:
            G_ScanFlag=1    #设置标志位
            
        for ip in self.IpList:
            if threading.activeCount()>256:
                time.sleep(1)
            if G_ScanFlag==2:   #退出扫描
                self.ret_ScanRes.emit(u"[+]强制退出成功!\n","")  
                return
            th=threading.Thread(target=self.XC_scan,args=(ip,))
            th.start()
            threads.append(th)
        for t in threads:   #等待线程都退出
            t.join()
        G_ScanFlag=0       #扫描结束
        self.ret_ScanRes.emit(u"[+]扫描结束!","")  

            
         
    def XC_scan(self,ip):
        ip=str(ip)
        flag=0  #标记扫描匹配结果
        Left_txt=ip+"\t\tOpen "
        Right_txt=ip+"\n"        
        for port in self.PortList:
            soc=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            soc.settimeout(self.TimeOut)
            try:
                soc.connect((ip.strip(),int(port)))
                Left_txt+="%s " % str(port)
                flag=1
            except:
                continue 
        if flag==1:
            Left_txt+="\n"
            global mutex
            if mutex.acquire():  #判断锁
                self.ret_ScanRes.emit(Left_txt,Right_txt)
                mutex.release()   #释放锁                

    def GetHexRaw(self,txt):
        pattern=re.compile(r"^\S{8}[ ]{2}\S{2}")
        line=txt.strip()
        if len(line)<60:
            self.ret_res.emit(u"[!]处理失败!数据格式不标准!")
            return True            
        if line[58]!=" ":
            self.ret_res.emit(u"[!]处理失败!数据格式不标准!")
            return True                
        if pattern.match(line)==None:
            self.ret_res.emit(u"[!]处理失败!数据格式不标准!")
            return True
        tmp16=""
        tmp16+=line[10:58]
        return tmp16.replace(' ', '').replace('\n', '').decode('hex')
         
    
    

               
    def SendBigFile(self):
        global G_Singal
        global G_Raw
        pause=True
        for j in range(self.num):
            DT_Len=0 #统计发送数据大小
            while True:             #控制程序运行状态
                if G_Singal==0:     #停止
                    self.ret_status.emit(20)
                    self.ret_res.emit(u"[+]已停止发送!")
                    return
                elif G_Singal==2:   #暂停
                    if pause:
                        self.ret_status.emit(10)
                        self.ret_res.emit(u"[+]发送已暂停!")
                        pause=False
                    time.sleep(0.5)
                    continue
                elif G_Singal==1:   #运行
                    pause=True
                    break
                
            soc=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            #soc.setsockopt(socket.SOL_SOCKET,socket.SO_RCVTIMEO,2000)
            soc.settimeout(2)
            res=""
            try:
                soc.connect((self.ip,int(self.port)))
                self.ret_status.emit(1)
                self.ret_res.emit(u"[+]当前发送的文件:")
                self.ret_res.emit(self.BigFileName)
                self.ret_res.emit(u"[+]正在发送，请稍后...！")
                try:
                    fp=open(self.BigFileName,"r")
                except:
                    self.ret_res.emit(u"[+]读取文件失败!")
                    return
                #----------对文本内容格式进行判断-------------------------------------
                data=fp.readline()
                TXT_TYPE="" #标记文本格式
                if data!='':
                    try:
                        DT=self.GetHexRaw(data)
                        if DT!=True:
                            TXT_TYPE="HEX"
                            data=DT
                        else:
                            #self.ret_res.emit(u"[!]格式化处理失败！文件内容非Wireshark Hex Dump格式!")
                            self.ret_res.emit(u"[!]正在尝试以原文样式发送!")
                            data=data.replace("\n","\r\n")
                            TXT_TYPE="TXT"
                    except:
                        self.ret_res.emit(u"[!]格式化处理失败!")
                        
                    soc.send(data)#发送上面获取到的第一行数据
                    DT_Len+= len(data)                    
                        
                #----------对文本内容格式进行判断-------------------------------------
                i=0
                while True:
                    if G_Singal==0:     #停止
                        self.ret_status.emit(20)
                        self.ret_res.emit(u"[+]已停止发送!")                        
                        return                    
                    if i==50001:
                        i=0          

                    
                    if data!='' and TXT_TYPE=="HEX":
                        try:
                            data=fp.readline()                    
                            if not data:#读取文件结束
                                self.ret_res.emit(u"[+]文件全部发送完毕！\n\n")
                                break
                            data=self.GetHexRaw(data)
                            if data==True:#格式化处理失败
                                return
                        except:
                            self.ret_res.emit(u"[!]发送失败！文件内容非标准Wireshark Hex Dump格式!")
                            return
                        soc.send(data)
                        DT_Len+= len(data)
                    elif  TXT_TYPE=="TXT":
                        data=fp.read(512)
                        if not data:#读取文件结束
                            self.ret_res.emit(u"[+]文件全部发送完毕！\n\n")
                            break                        
                        data=data.replace("\n","\r\n")
                        soc.send(data)
                        DT_Len+= len(data)
                        
                    if i%10==0:
                        self.ret_num.emit(i+1)
                    i=i+1                        
                   
                try:
                    res=""
                    while True:
                        buf=soc.recv(1024)
                        res+=buf
                        if not len(buf):        #判断数据是否接收完毕
                            break
                    self.ret_res.emit(u"<font color=red>▼Send Num:[ %d ]  Recv Data:[ %d ]Byte</font>" % ((j+1),len(res)))
                    if G_Raw==1:
                        res=self.Raw_Decode(res)
                    elif G_Raw==2:
                        res=self.Raw_pack(res)
                    self.ret_res.emit(res)
                except:
                    if res!="":
                        self.ret_res.emit(u"<font color=red>▼Send Num:[ %d ]  Recv Data:[ %d ]Byte</font>" % ((j+1),len(res)))
                        if G_Raw==1:
                            res=self.Raw_Decode(res)   
                        elif G_Raw==2:
                            res=self.Raw_pack(res)                        
                        self.ret_res.emit(res) 
                    else:
                        self.ret_res.emit(u"<font color=red>▼Send Num:[ %d ]  Recv Data:[ %d ]Byte</font>" % ((j+1),len(res)))
                        self.ret_res.emit(u"[+]未收到返回数据!")
            except:
                self.ret_status.emit(2)
                self.ret_res.emit(u"<font color=red>▼Send Num:[ %d ]  Send Data:[ %d ]Byte</font>" % ((j+1),DT_Len))
                self.ret_res.emit(u"<font color=red><br>[!]Socket连接异常....</font><br>")
                
            self.ret_num.emit(j+1)
            time.sleep(self.stime)
        self.ret_status.emit(3)
        
               
               
                
                
    def send_data(self,R_S):
        global G_Singal
        global G_Raw
        pause=True
        for i in range(self.num):
            while True:             #控制程序运行状态
                if G_Singal==0:     #停止
                    self.ret_status.emit(20)
                    self.ret_res.emit(u"[+]已停止发送!")
                    return
                elif G_Singal==2:   #暂停
                    if pause:
                        self.ret_status.emit(10)
                        self.ret_res.emit(u"[+]发送已暂停!")
                        pause=False
                    time.sleep(0.5)
                    continue
                elif G_Singal==1:   #运行
                    pause=True
                    break
                
            soc=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            #soc.setsockopt(socket.SOL_SOCKET,socket.SO_RCVTIMEO,2000)
            soc.settimeout(2)
            try:
                soc.connect((self.ip,int(self.port)))
                try:
                    if(R_S=="Normal"):
                        soc.send(self.data)
                    elif(R_S=="Random"):
                        DataSize=0              #保存数据发送大小
                        while True:
                            #**************************************************************************
                            #*
                            if G_Singal==0:     #停止                                                
                                self.ret_status.emit(20)                                             
                                self.ret_res.emit(u"[+]已停止发送!")                                  
                                return                                                               
                            elif G_Singal==2:   #暂停                                                
                                if pause:                                                            
                                    self.ret_status.emit(10)                                         
                                    self.ret_res.emit(u"[+]发送已暂停!")                             
                                    pause=False                                                      
                                time.sleep(1)                                                      
                                continue                                                             
                            elif G_Singal==1:   #运行                                                
                                pause=True      
                                soc.send(chr(random.randint(1,127))*128) #发送随机数据
                                DataSize+=128
                                if (DataSize%102400)==0:
                                    self.ret_res.emit(u"[+]正在发送...{已发送数据大小: %d KB}" %(DataSize/1024))
                            #*                                                                        
                            #**************************************************************************
                except:
                    self.ret_res.emit(u"<font color=red><br>[!]Socket连接已断开!{本次发送数据大小: %d KB}</font><br>" %(DataSize/1024))
                    time.sleep(self.stime)
                    self.ret_num.emit(i+1)
                    continue
                self.ret_status.emit(1)
                try:
                    res=""
                    while True:
                        buf=soc.recv(1024)
                        res+=buf
                        if not len(buf):        #判断数据是否接收完毕
                            break
                    
                    
                    self.ret_res.emit(u"\n<font color=red>▼Send Num:[ %d ]  Recv Data:[ %d ]Byte</font>\n" % ((i+1),len(res)))
                    if G_Raw==1:
                        res=self.Raw_Decode(res)
                    elif G_Raw==2:
                        res=self.Raw_pack(res)
                    self.ret_res.emit(res)
                except:
                    if res!="":
                        self.ret_res.emit(u"\n<font color=red>▼Send Num:[ %d ]  Recv Data:[ %d ]Byte</font>\n" % ((i+1),len(res)))
                        if G_Raw==1:
                            res=self.Raw_Decode(res)   
                        elif G_Raw==2:
                            res=self.Raw_pack(res)                        
                        self.ret_res.emit(res) 
                    else:
                        self.ret_res.emit(u"\n<font color=red>▼Send Num:[ %d ]  Recv Data:[ %d ]Byte</font>\n" % ((i+1),len(res)))
                        self.ret_res.emit(u"[+]未收到返回数据!")
            except:
                self.ret_status.emit(2)
                self.ret_res.emit(u"<font color=red><br>[!]Socket连接异常....<br></font>")
            self.ret_num.emit(i+1)
            time.sleep(self.stime)
        self.ret_status.emit(3)


    def send_data_udp(self,R_S):
        global G_Singal
        pause=True
        for i in range(self.num):
            while True:             #控制程序运行状态
                if G_Singal==0:     #停止
                    self.ret_status.emit(20)
                    self.ret_res.emit(u"[+]已停止发送!")
                    return
                elif G_Singal==2:   #暂停
                    if pause:
                        self.ret_status.emit(10)
                        self.ret_res.emit(u"[+]发送已暂停!")
                        pause=False
                    time.sleep(0.5)
                    continue
                elif G_Singal==1:   #运行
                    pause=True
                    break
                
            soc=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            
            if R_S=="Multicast":            #组播
                localIP = socket.gethostbyname(socket.gethostname())#这个得到本地ip
                soc.bind((localIP, 52345))

                
            addr=(self.ip,self.port)
            soc.settimeout(2)
            try:
                soc.sendto(self.data,addr)
            except:
                self.ret_status.emit(4)     #发送的数据内容编码不支持
                self.ret_res.emit(u"[+]发送失败!")
                time.sleep(self.stime)
                self.ret_num.emit(i+1)
                continue
            self.ret_status.emit(1)
            if R_S=="Recv" or R_S=="Multicast":
                try:
                    res=""
                    while True:
                        buf,adr=soc.recvfrom(1024)
                        if not len(buf):        #判断数据是否接收完毕
                            break

                        if R_S=="Multicast":
                            data="[+]Data Form IP:(%s:%s)\n" % (adr[0],adr[1])
                            buf=data+buf
                            
                        res+=buf
                        
                    self.ret_res.emit(u"\n<font color=red>▼Send Num:[ %d ]  Recv Data:[ %d ]Byte</font>\n" % ((i+1),len(res)))
                    if G_Raw==1:
                        res=self.Raw_Decode(res)  
                    elif G_Raw==2:
                        res=self.Raw_pack(res)                    
                    self.ret_res.emit(res)
                except:
                    if res!="":
                        self.ret_res.emit(u"\n<font color=red>▼Send Num:[ %d ]  Recv Data:[ %d ]Byte</font>\n" % ((i+1),len(res)))
                        if G_Raw==1:
                            res=self.Raw_Decode(res) 
                        elif G_Raw==2:
                            res=self.Raw_pack(res)                        
                        self.ret_res.emit(res)   
                    else:
                        self.ret_res.emit(u"\n<font color=red>▼Send Num:[ %d ]  Recv Data:[ %d ]Byte</font>\n" % ((i+1),len(res)))
                        self.ret_res.emit(u"[+]未收到返回数据!")
                self.ret_num.emit(i+1)
            elif R_S=="Send":
                if (self.num-i)<10:
                    self.ret_res.emit(u"[+]正在发送...")
                    self.ret_num.emit(i+1)
                else:
                    if i%200==0:
                        self.ret_res.emit(u"[+]正在发送...")
                        self.ret_num.emit(i+1)                        
            time.sleep(self.stime)
        self.ret_status.emit(3)
        
    def Raw_Decode(self,buf):
        Hex16=binascii.hexlify(buf)
        Tmp=""
        for i in range(0,len(Hex16),2):
            if (i % 32)==0 and i!=0:
                Tmp+="\n"+Hex16[i:i+2]+" "
            elif (i % 16)==0 and i!=0:
                Tmp+="  "+Hex16[i:i+2]+" "
            else:
                Tmp+=Hex16[i:i+2]+" "
        return Tmp
    
        def Raw_pack(self,buf):
            res=""
            for i in range(len(buf)):
                asc=struct.unpack("!c",buf[i])
                if ord(asc[0])>19 and ord(asc[0])<127:
                    res+=asc[0]
                else:
                    res+="."
            return res
    
    
    
    
class Ui_MainWindow(QtGui.QMainWindow):
    def __init__(self):
        super(Ui_MainWindow,self).__init__()
        self.setupUi(self)
        self.retranslateUi(self) 
        self.Init_User()                #初始化
        self.thread =workthread()        #多线程对象


        #多线程信息槽连接   ----------------------------------------------------------------------
        self.thread.ret_num.connect(self.setJD)
        self.thread.ret_res.connect(self.Lf_showlog)
        self.thread.ret_status.connect(self.setStatus)
        self.thread.ret_ScanRes.connect(self.write_ip)
        #信号槽连接
        #  主窗口      ---------------------------------------------------------------------------    
        self.connect(self.B_send,QtCore.SIGNAL('clicked()'),self.f_send)
        self.connect(self.B_pause,QtCore.SIGNAL('clicked()'),self.f_pause)
        self.connect(self.B_reset,QtCore.SIGNAL('clicked()'),self.f_reset)
        self.connect(self.B_stop,QtCore.SIGNAL('clicked()'),self.f_stop)
        self.connect(self.B_test,QtCore.SIGNAL('clicked()'),self.f_test)
        #  数据窗口    ---------------------------------------------------------------------------
        self.connect(self.DB_16,QtCore.SIGNAL('clicked()'),self.Df_DB_16)
        self.connect(self.DB_16LX,QtCore.SIGNAL('clicked()'),self.Df_DB_16LX)
        self.connect(self.DB_8,QtCore.SIGNAL('clicked()'),self.Df_DB_8)
        self.connect(self.DB_Flush,QtCore.SIGNAL('clicked()'),self.Df_DB_Flush)
        self.connect(self.DB_Initdata,QtCore.SIGNAL('clicked()'),self.Df_DB_Initdata)
        self.connect(self.comboBox_Rz,QtCore.SIGNAL('activated(int)'),self.Df_comboBox_Rz)
        self.connect(self.comboBox_raw,QtCore.SIGNAL('activated(int)'),self.Df_comboBox_Raw)
        #  Log窗口     ---------------------------------------------------------------------------
        self.connect(self.LogB_Flush,QtCore.SIGNAL('clicked()'),self.Lf_DB_Flush)
        #  编解码窗口  ---------------------------------------------------------------------------  
        self.connect(self.comboBox_BM,QtCore.SIGNAL('activated(int)'),self.Bf_comboBox_BM)
        self.connect(self.BBM_BM,QtCore.SIGNAL('clicked()'),self.Bf_BBM_BM)
        self.connect(self.BBM_JM,QtCore.SIGNAL('clicked()'),self.Bf_BBM_JM)
        self.connect(self.BBM_Change,QtCore.SIGNAL('clicked()'),self.Bf_BBM_Change)
        self.connect(self.BBM_Flush,QtCore.SIGNAL('clicked()'),self.Bf_BBM_Flush)
        self.connect(self.BBM_JSQ,QtCore.SIGNAL('clicked()'),self.Bf_BBM_JSQ)
        #生成用例窗口-----------------------------------------------------------------------------
        self.connect(self.B_YL_PY,QtCore.SIGNAL('clicked()'),self.Bf_LY_Make_py)
        self.connect(self.B_YL_reset,QtCore.SIGNAL('clicked()'),self.Bf_LY_reset)
        self.connect(self.B_YL_open,QtCore.SIGNAL('clicked()'),self.Bf_LY_open)        
        self.connect(self.B_YL_flush,QtCore.SIGNAL('clicked()'),self.Bf_LY_reflush)  
        #端口扫描       --------------------------------------------------------------------------
        self.connect(self.B_ScanPort,QtCore.SIGNAL('clicked()'),self.Port_scan) 



    def setupUi(self, MainWindow):
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(730, 509)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setMinimumSize(QtCore.QSize(730, 509))
        MainWindow.setMaximumSize(QtCore.QSize(730, 509))
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        self.Label_Ip = QtGui.QLabel(self.centralwidget)
        self.Label_Ip.setGeometry(QtCore.QRect(390, 10, 16, 20))
        self.Label_Ip.setObjectName(_fromUtf8("Label_Ip"))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.Label_Ip.setFont(font)          
        
        self.B_send = QtGui.QPushButton(self.centralwidget)
        self.B_send.setGeometry(QtCore.QRect(660, 10, 51, 51))
        font = QtGui.QFont()
        #font.setFamily(_fromUtf8("Agency FB"))
        font.setPointSize(14)
        ##font.setWeight(50)
        self.B_send.setFont(font)
        self.B_send.setObjectName(_fromUtf8("B_send"))
        self.layoutWidget = QtGui.QWidget(self.centralwidget)
        self.layoutWidget.setGeometry(QtCore.QRect(20, 10, 257, 18))
        self.layoutWidget.setObjectName(_fromUtf8("layoutWidget"))
        self.gridLayout = QtGui.QGridLayout(self.layoutWidget)
        self.gridLayout.setMargin(0)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.radio_wireshark = QtGui.QRadioButton(self.layoutWidget)
        self.radio_wireshark.setChecked(True)
        self.radio_wireshark.setObjectName(_fromUtf8("radio_wireshark"))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.radio_wireshark.setFont(font)        
        
        self.gridLayout.addWidget(self.radio_wireshark, 0, 0, 1, 1)
        self.radio_16 = QtGui.QRadioButton(self.layoutWidget)
        self.radio_16.setObjectName(_fromUtf8("radio_16"))
        self.gridLayout.addWidget(self.radio_16, 0, 1, 1, 1)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.radio_16.setFont(font)  
        
        self.radio_text = QtGui.QRadioButton(self.layoutWidget)
        self.radio_text.setObjectName(_fromUtf8("radio_text"))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.radio_text.setFont(font)  
        
        self.gridLayout.addWidget(self.radio_text, 0, 2, 1, 1)
        self.tabWidget = QtGui.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(20, 71, 691, 421))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.tabWidget.setFont(font)
        self.tabWidget.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.tabWidget.setDocumentMode(True)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.tab_Data = QtGui.QWidget()
        self.tab_Data.setObjectName(_fromUtf8("tab_Data"))
        self.Edit_data = QtGui.QTextEdit(self.tab_Data)
        self.Edit_data.setGeometry(QtCore.QRect(0, 30, 691, 371))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.Edit_data.setFont(font)
        self.Edit_data.setFrameShadow(QtGui.QFrame.Plain)
        self.Edit_data.setLineWidth(1)
        self.Edit_data.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.Edit_data.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.Edit_data.setObjectName(_fromUtf8("Edit_data"))
        self.DB_16LX = QtGui.QPushButton(self.tab_Data)
        self.DB_16LX.setGeometry(QtCore.QRect(70, 5, 75, 23))
        self.DB_16LX.setObjectName(_fromUtf8("DB_16LX"))
        self.DB_16 = QtGui.QPushButton(self.tab_Data)
        self.DB_16.setGeometry(QtCore.QRect(150, 5, 71, 23))
        self.DB_16.setObjectName(_fromUtf8("DB_16"))
        self.DB_8 = QtGui.QPushButton(self.tab_Data)
        self.DB_8.setGeometry(QtCore.QRect(225, 5, 61, 23))
        self.DB_8.setObjectName(_fromUtf8("DB_8"))
        self.DB_Flush = QtGui.QPushButton(self.tab_Data)
        self.DB_Flush.setGeometry(QtCore.QRect(290, 5, 61, 23))
        self.DB_Flush.setObjectName(_fromUtf8("DB_Flush"))
        self.DB_Initdata = QtGui.QPushButton(self.tab_Data)
        self.DB_Initdata.setGeometry(QtCore.QRect(0, 5, 65, 23))
        self.DB_Initdata.setObjectName(_fromUtf8("DB_Initdata"))
        self.comboBox_Rz = QtGui.QComboBox(self.tab_Data)
        self.comboBox_Rz.setGeometry(QtCore.QRect(360, 5, 65, 23))
        self.comboBox_Rz.setObjectName(_fromUtf8("comboBox_Rz"))
        self.comboBox_Rz.addItem(_fromUtf8(""))
        self.comboBox_Rz.addItem(_fromUtf8(""))
        self.comboBox_Rz.addItem(_fromUtf8(""))
        self.comboBox_Rz.addItem(_fromUtf8(""))
        self.comboBox_Rz.addItem(_fromUtf8(""))
        self.comboBox_Rz.addItem(_fromUtf8(""))
        self.comboBox_Rz.addItem(_fromUtf8(""))
        self.comboBox_Rz.addItem(_fromUtf8(""))



        self.Password = QtGui.QLineEdit(self.tab_Data)
        self.Password.setGeometry(QtCore.QRect(591, 5, 100, 23))
        self.Password.setObjectName(_fromUtf8("Password"))
        self.label_pwd = QtGui.QLabel(self.tab_Data)
        self.label_pwd.setGeometry(QtCore.QRect(558, 5, 31, 23))
        self.label_pwd.setObjectName(_fromUtf8("label_pwd"))
        self.Username = QtGui.QLineEdit(self.tab_Data)
        self.Username.setGeometry(QtCore.QRect(480, 5, 71, 23))
        self.Username.setObjectName(_fromUtf8("Username"))
        self.label_user = QtGui.QLabel(self.tab_Data)
        self.label_user.setGeometry(QtCore.QRect(430, 5, 54, 23))
        self.label_user.setObjectName(_fromUtf8("label_user"))
        self.tabWidget.addTab(self.tab_Data, _fromUtf8(""))
        self.tab_Log = QtGui.QWidget()
        self.tab_Log.setObjectName(_fromUtf8("tab_Log"))
        self.Show_Log = QtGui.QTextEdit(self.tab_Log)
        self.Show_Log.setGeometry(QtCore.QRect(0, 20, 691, 381))
        self.Show_Log.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.Show_Log.setReadOnly(True)
        self.Show_Log.setObjectName(_fromUtf8("Show_Log"))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.Show_Log.setFont(font)        
        
        self.LogB_Flush = QtGui.QPushButton(self.tab_Log)
        self.LogB_Flush.setGeometry(QtCore.QRect(0, 0, 611, 20))
        self.LogB_Flush.setObjectName(_fromUtf8("LogB_Flush"))



        self.comboBox_raw = QtGui.QComboBox(self.tab_Log)
        self.comboBox_raw.setGeometry(QtCore.QRect(610, 0, 81, 20))
        self.comboBox_raw.setObjectName(_fromUtf8("comboBox_raw"))
        self.comboBox_raw.addItem(_fromUtf8(""))
        self.comboBox_raw.addItem(_fromUtf8(""))
        self.comboBox_raw.addItem(_fromUtf8(""))


        self.tabWidget.addTab(self.tab_Log, _fromUtf8(""))
        self.tab_Bjm = QtGui.QWidget()
        self.tab_Bjm.setObjectName(_fromUtf8("tab_Bjm"))
        self.comboBox_BM = QtGui.QComboBox(self.tab_Bjm)
        self.comboBox_BM.setGeometry(QtCore.QRect(0, 10, 121, 22))
        self.comboBox_BM.setObjectName(_fromUtf8("comboBox_BM"))
        self.comboBox_BM.addItem(_fromUtf8(""))
        self.comboBox_BM.addItem(_fromUtf8(""))
        self.comboBox_BM.addItem(_fromUtf8(""))
        self.comboBox_BM.addItem(_fromUtf8(""))
        self.comboBox_BM.addItem(_fromUtf8(""))
        self.textEdit_Data = QtGui.QTextEdit(self.tab_Bjm)
        self.textEdit_Data.setGeometry(QtCore.QRect(0, 60, 691, 151))
        self.textEdit_Data.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.textEdit_Data.setObjectName(_fromUtf8("textEdit_Data"))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.textEdit_Data.setFont(font)        
        
        self.textEdit_Res = QtGui.QTextEdit(self.tab_Bjm)
        self.textEdit_Res.setGeometry(QtCore.QRect(0, 230, 691, 171))
        self.textEdit_Res.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.textEdit_Res.setReadOnly(True)
        self.textEdit_Res.setObjectName(_fromUtf8("textEdit_Res"))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.textEdit_Res.setFont(font)         
        
        
        self.BBM_BM = QtGui.QPushButton(self.tab_Bjm)
        self.BBM_BM.setGeometry(QtCore.QRect(140, 10, 61, 23))
        self.BBM_BM.setObjectName(_fromUtf8("BBM_BM"))
        self.BBM_JM = QtGui.QPushButton(self.tab_Bjm)
        self.BBM_JM.setGeometry(QtCore.QRect(230, 10, 61, 23))
        self.BBM_JM.setObjectName(_fromUtf8("BBM_JM"))
        self.BBM_Change = QtGui.QPushButton(self.tab_Bjm)
        self.BBM_Change.setGeometry(QtCore.QRect(320, 10, 61, 23))
        self.BBM_Change.setObjectName(_fromUtf8("BBM_Change"))
        self.BBM_Flush = QtGui.QPushButton(self.tab_Bjm)
        self.BBM_Flush.setGeometry(QtCore.QRect(420, 10, 75, 23))
        self.BBM_Flush.setObjectName(_fromUtf8("BBM_Flush"))

        self.BBM_JSQ = QtGui.QPushButton(self.tab_Bjm)#计算器
        self.BBM_JSQ.setGeometry(QtCore.QRect(620, 10, 60, 23))
        self.BBM_JSQ.setObjectName(_fromUtf8("BBM_JSQ"))        

        self.tabWidget.addTab(self.tab_Bjm, _fromUtf8(""))
        self.label = QtGui.QLabel(self.tab_Bjm)
        self.label.setGeometry(QtCore.QRect(0, 40, 41, 16))
        self.label.setObjectName(_fromUtf8("label"))
        self.label_2 = QtGui.QLabel(self.tab_Bjm)
        self.label_2.setGeometry(QtCore.QRect(0, 213, 71, 16))
        self.label_2.setObjectName(_fromUtf8("label_2"))  

        self.tab_LY = QtGui.QWidget()
        self.tab_LY.setObjectName(_fromUtf8("tab_LY"))
        self.tabWidget_LY = QtGui.QTabWidget(self.tab_LY)
        self.tabWidget_LY.setGeometry(QtCore.QRect(0, 20, 631, 371))
        self.tabWidget_LY.setTabPosition(QtGui.QTabWidget.West)
        self.tabWidget_LY.setObjectName(_fromUtf8("tabWidget_LY"))
        self.tab_2 = QtGui.QWidget()
        self.tab_2.setObjectName(_fromUtf8("tab_2"))
        self.plainTextEdit_txt = QtGui.QPlainTextEdit(self.tab_2)
        self.plainTextEdit_txt.setGeometry(QtCore.QRect(0, 0, 611, 371))
        self.plainTextEdit_txt.setObjectName(_fromUtf8("plainTextEdit_txt"))
        self.tabWidget_LY.addTab(self.tab_2, _fromUtf8(""))
        self.tab_3 = QtGui.QWidget()
        self.tab_3.setObjectName(_fromUtf8("tab_3"))
        self.plainTextEdit_code = QtGui.QPlainTextEdit(self.tab_3)
        self.plainTextEdit_code.setGeometry(QtCore.QRect(0, 0, 611, 371))
        self.plainTextEdit_code.setObjectName(_fromUtf8("plainTextEdit_code"))
        self.tabWidget_LY.addTab(self.tab_3, _fromUtf8(""))
        self.B_YL_PY = QtGui.QPushButton(self.tab_LY)
        self.B_YL_PY.setGeometry(QtCore.QRect(630, 20, 61, 23))
        self.B_YL_PY.setObjectName(_fromUtf8("B_YL_PY"))
        self.B_YL_reset = QtGui.QPushButton(self.tab_LY)
        self.B_YL_reset.setGeometry(QtCore.QRect(630, 70, 61, 23))
        self.B_YL_reset.setObjectName(_fromUtf8("B_YL_reset"))
        self.B_YL_open = QtGui.QPushButton(self.tab_LY)
        self.B_YL_open.setGeometry(QtCore.QRect(630, 120, 61, 23))
        self.B_YL_open.setObjectName(_fromUtf8("B_YL_open"))

        self.B_YL_flush = QtGui.QPushButton(self.tab_LY)
        self.B_YL_flush.setGeometry(QtCore.QRect(630, 170, 61, 23))
        self.B_YL_flush.setObjectName(_fromUtf8("B_YL_flush"))


        self.tabWidget.addTab(self.tab_LY, _fromUtf8(""))        

        self.tab = QtGui.QWidget()
        self.tab.setObjectName(_fromUtf8("tab"))


        self.plainTextEdit_left = QtGui.QPlainTextEdit(self.tab)
        self.plainTextEdit_left.setGeometry(QtCore.QRect(2, 0, 391, 401))
        self.plainTextEdit_left.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.plainTextEdit_left.setReadOnly(True)
        self.plainTextEdit_left.setObjectName(_fromUtf8("plainTextEdit_left"))
        self.B_ScanPort = QtGui.QPushButton(self.tab)
        self.B_ScanPort.setGeometry(QtCore.QRect(580, 90, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.B_ScanPort.setFont(font)
        self.B_ScanPort.setObjectName(_fromUtf8("B_ScanPort"))
        self.Scan_IP = QtGui.QLineEdit(self.tab)
        self.Scan_IP.setGeometry(QtCore.QRect(490, 10, 201, 31))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.Scan_IP.setFont(font)
        self.Scan_IP.setObjectName(_fromUtf8("Scan_IP"))
        self.SpinBox_Timeout = QtGui.QDoubleSpinBox(self.tab)
        self.SpinBox_Timeout.setGeometry(QtCore.QRect(490, 90, 81, 31))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.SpinBox_Timeout.setFont(font)
        self.SpinBox_Timeout.setDecimals(1)
        self.SpinBox_Timeout.setMaximum(10.0)
        self.SpinBox_Timeout.setSingleStep(0.1)
        self.SpinBox_Timeout.setProperty("value", 0.5)
        self.SpinBox_Timeout.setObjectName(_fromUtf8("SpinBox_Timeout"))
        self.label_3 = QtGui.QLabel(self.tab)
        self.label_3.setGeometry(QtCore.QRect(400, 9, 81, 31))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_3.setFont(font)
        self.label_3.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_3.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.label_4 = QtGui.QLabel(self.tab)
        self.label_4.setGeometry(QtCore.QRect(400, 50, 81, 31))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_4.setFont(font)
        self.label_4.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.label_5 = QtGui.QLabel(self.tab)
        self.label_5.setGeometry(QtCore.QRect(400, 90, 81, 31))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_5.setFont(font)
        self.label_5.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.label_5.setObjectName(_fromUtf8("label_5"))
        self.Scan_port_1 = QtGui.QLineEdit(self.tab)
        self.Scan_port_1.setGeometry(QtCore.QRect(490, 50, 201, 31))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.Scan_port_1.setFont(font)
        self.Scan_port_1.setCursor(QtGui.QCursor(QtCore.Qt.IBeamCursor))
        self.Scan_port_1.setAlignment(QtCore.Qt.AlignCenter)
        self.Scan_port_1.setObjectName(_fromUtf8("Scan_port_1"))

        self.plainTextEdit_right = QtGui.QPlainTextEdit(self.tab)
        self.plainTextEdit_right.setGeometry(QtCore.QRect(400, 130, 291, 271))
        self.plainTextEdit_right.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.plainTextEdit_right.setReadOnly(True)
        self.plainTextEdit_right.setObjectName(_fromUtf8("plainTextEdit_right"))        
        self.tabWidget.addTab(self.tab, _fromUtf8(""))        

        self.comboBox = QtGui.QComboBox(self.tab_Bjm)
        self.comboBox.setGeometry(QtCore.QRect(530, 10, 69, 23))
        self.comboBox.setObjectName(_fromUtf8("comboBox"))
        self.comboBox.addItem(_fromUtf8(""))
        self.comboBox.addItem(_fromUtf8(""))
        self.comboBox.addItem(_fromUtf8(""))    





        self.progressBar = QtGui.QProgressBar(self.centralwidget)
        self.progressBar.setGeometry(QtCore.QRect(20, 491, 691, 16))
        self.progressBar.setMaximum(1)
        self.progressBar.setProperty("value", 0)
        self.progressBar.setAlignment(QtCore.Qt.AlignCenter)
        self.progressBar.setTextVisible(True)
        self.progressBar.setInvertedAppearance(False)
        self.progressBar.setObjectName(_fromUtf8("progressBar"))
        self.Label_Num = QtGui.QLabel(self.centralwidget)
        self.Label_Num.setGeometry(QtCore.QRect(195, 41, 51, 20))
        self.Label_Num.setObjectName(_fromUtf8("Label_Num"))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.Label_Num.setFont(font)    
        
        self.B_test = QtGui.QPushButton(self.centralwidget)
        self.B_test.setGeometry(QtCore.QRect(590, 40, 61, 23))
        self.B_test.setObjectName(_fromUtf8("B_test"))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.B_test.setFont(font)        
        self.B_pause = QtGui.QPushButton(self.centralwidget)
        self.B_pause.setGeometry(QtCore.QRect(490, 40, 41, 23))
        self.B_pause.setObjectName(_fromUtf8("B_pause"))
        
        font = QtGui.QFont()
        font.setPointSize(12)
        self.B_pause.setFont(font)
        
        self.B_stop = QtGui.QPushButton(self.centralwidget)
        self.B_stop.setGeometry(QtCore.QRect(540, 40, 41, 23))
        self.B_stop.setObjectName(_fromUtf8("B_stop"))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.B_stop.setFont(font)
        
        self.Show_Status = QtGui.QLabel(self.centralwidget)
        self.Show_Status.setGeometry(QtCore.QRect(23, 40, 100, 20))
        self.Show_Status.setObjectName(_fromUtf8("Show_Status"))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.Show_Status.setFont(font)        
        
        self.CheckBox_Enter = QtGui.QCheckBox(self.centralwidget)
        self.CheckBox_Enter.setGeometry(QtCore.QRect(280, 10, 81, 20))
        self.CheckBox_Enter.setObjectName(_fromUtf8("CheckBox_Enter"))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.CheckBox_Enter.setFont(font)        
        
        self.Label_Port = QtGui.QLabel(self.centralwidget)
        self.Label_Port.setGeometry(QtCore.QRect(562, 10, 24, 20))
        self.Label_Port.setObjectName(_fromUtf8("Label_Port"))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.Label_Port.setFont(font) 

        self.comboBox_raw.setItemText(0, _translate("MainWindow", "解码明文", None))
        self.comboBox_raw.setItemText(1, _translate("MainWindow", "进制流", None))
        self.comboBox_raw.setItemText(2, _translate("MainWindow", "ASCII字符", None))

        self.Target_Ip = QtGui.QLineEdit(self.centralwidget)
        self.Target_Ip.setGeometry(QtCore.QRect(406, 10, 151, 20))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.Target_Ip.setFont(font)
        self.Target_Ip.setMaxLength(15)
        self.Target_Ip.setAlignment(QtCore.Qt.AlignCenter)
        self.Target_Ip.setObjectName(_fromUtf8("Target_Ip"))
        self.Label_Time = QtGui.QLabel(self.centralwidget)
        self.Label_Time.setGeometry(QtCore.QRect(320, 41, 54, 23))
        self.Label_Time.setObjectName(_fromUtf8("Label_Time"))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.Label_Time.setFont(font)         
        
        self.Label_S = QtGui.QLabel(self.centralwidget)
        self.Label_S.setGeometry(QtCore.QRect(423, 41, 16, 23))

        self.B_ScanPort.setText(_translate("MainWindow", "扫描", None))
        self.label_3.setText(_translate("MainWindow", "IP:", None))
        self.label_4.setText(_translate("MainWindow", "Port:", None))
        self.label_5.setText(_translate("MainWindow", "TimeOut:", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("MainWindow", "端口扫描", None))        

        self.Label_S.setObjectName(_fromUtf8("Label_S"))
        self.B_reset = QtGui.QPushButton(self.centralwidget)
        self.B_reset.setGeometry(QtCore.QRect(440, 40, 41, 23))
        self.B_reset.setObjectName(_fromUtf8("B_reset"))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.B_reset.setFont(font)        
        
        
        self.SpinBox_Num = QtGui.QSpinBox(self.centralwidget)
        self.SpinBox_Num.setGeometry(QtCore.QRect(250, 41, 61, 22))
        self.SpinBox_Num.setMinimum(1)
        self.SpinBox_Num.setMaximum(999999)
        self.SpinBox_Num.setObjectName(_fromUtf8("SpinBox_Num"))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.SpinBox_Num.setFont(font)  
        
        self.SpinBox_Time = QtGui.QDoubleSpinBox(self.centralwidget)
        self.SpinBox_Time.setGeometry(QtCore.QRect(370, 41, 51, 22))
        self.SpinBox_Time.setDecimals(1)
        self.SpinBox_Time.setObjectName(_fromUtf8("SpinBox_Time"))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.SpinBox_Time.setFont(font)        
        
        self.Target_Port = QtGui.QSpinBox(self.centralwidget)
        self.Target_Port.setGeometry(QtCore.QRect(590, 10, 61, 22))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.Target_Port.setFont(font)
        self.Target_Port.setCursor(QtGui.QCursor(QtCore.Qt.IBeamCursor))
        self.Target_Port.setAlignment(QtCore.Qt.AlignCenter)
        self.Target_Port.setButtonSymbols(QtGui.QAbstractSpinBox.NoButtons)
        self.Target_Port.setMaximum(65535)
        self.Target_Port.setObjectName(_fromUtf8("Target_Port"))
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        self.tabWidget_LY.setCurrentIndex(0)

        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        MainWindow.setTabOrder(self.Target_Ip, self.Target_Port)
        MainWindow.setTabOrder(self.Target_Port, self.SpinBox_Num)
        MainWindow.setTabOrder(self.SpinBox_Num, self.SpinBox_Time)
        MainWindow.setTabOrder(self.SpinBox_Time, self.tabWidget)
        MainWindow.setTabOrder(self.tabWidget, self.Edit_data)
        MainWindow.setTabOrder(self.Edit_data, self.radio_wireshark)
        MainWindow.setTabOrder(self.radio_wireshark, self.radio_16)
        MainWindow.setTabOrder(self.radio_16, self.radio_text)
        MainWindow.setTabOrder(self.radio_text, self.CheckBox_Enter)
        MainWindow.setTabOrder(self.CheckBox_Enter, self.DB_Initdata)
        MainWindow.setTabOrder(self.DB_Initdata, self.DB_16LX)
        MainWindow.setTabOrder(self.DB_16LX, self.DB_16)
        MainWindow.setTabOrder(self.DB_16, self.DB_8)
        MainWindow.setTabOrder(self.DB_8, self.DB_Flush)
        MainWindow.setTabOrder(self.DB_Flush, self.B_reset)
        MainWindow.setTabOrder(self.B_reset, self.B_pause)
        MainWindow.setTabOrder(self.B_pause, self.B_stop)
        MainWindow.setTabOrder(self.B_stop, self.B_test)
        MainWindow.setTabOrder(self.B_test, self.B_send)
        MainWindow.setTabOrder(self.B_send, self.Show_Log)
        MainWindow.setTabOrder(self.Show_Log, self.LogB_Flush)
        MainWindow.setTabOrder(self.LogB_Flush, self.textEdit_Data)
        MainWindow.setTabOrder(self.textEdit_Data, self.comboBox_BM)
        MainWindow.setTabOrder(self.comboBox_BM, self.BBM_BM)
        MainWindow.setTabOrder(self.BBM_BM, self.BBM_JM)
        MainWindow.setTabOrder(self.BBM_JM, self.BBM_Change)
        MainWindow.setTabOrder(self.BBM_Change, self.BBM_Flush)
        MainWindow.setTabOrder(self.BBM_Flush, self.textEdit_Res)
        MainWindow.setTabOrder(self.Scan_IP, self.Scan_port_1)
        MainWindow.setTabOrder(self.Scan_port_1,self.SpinBox_Timeout)


    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "By Topper 2016.01", None))
        self.Label_Ip.setText(_translate("MainWindow", "IP", None))
        self.B_send.setText(_translate("MainWindow", "发送", None))
        self.radio_wireshark.setText(_translate("MainWindow", "WireShark流", None))
        self.radio_16.setText(_translate("MainWindow", "纯16进制流", None))
        self.radio_text.setText(_translate("MainWindow", "正常文本", None))
        self.DB_16LX.setText(_translate("MainWindow", "连续16进制", None))
        self.DB_16.setText(_translate("MainWindow", "16位分割", None))
        self.DB_8.setText(_translate("MainWindow", "8位分割", None))
        self.DB_Flush.setText(_translate("MainWindow", "清空", None))
        self.DB_Initdata.setText(_translate("MainWindow", "原始数据", None))
        self.comboBox_Rz.setItemText(0, _translate("MainWindow", "TCP流", None))
        self.comboBox_Rz.setItemText(1, _translate("MainWindow", "Basic", None))
        self.comboBox_Rz.setItemText(2, _translate("MainWindow", "Digest", None))
        self.comboBox_Rz.setItemText(3, _translate("MainWindow", "UDP-Recv", None))
        self.comboBox_Rz.setItemText(4, _translate("MainWindow", "UDP-Send", None))
        self.comboBox_Rz.setItemText(5, _translate("MainWindow", "UDP-组播", None))
        self.comboBox_Rz.setItemText(6, _translate("MainWindow", "TCP-随机", None))
        self.comboBox_Rz.setItemText(7, _translate("MainWindow", "发送文本", None))
    
        self.label_pwd.setText(_translate("MainWindow", "密码:", None))
        self.label_user.setText(_translate("MainWindow", "用户名:", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_Data), _translate("MainWindow", "数据窗口", None))
        self.Show_Log.setWhatsThis(_translate("MainWindow", "<html><head/><body><p>14</p></body></html>", None))
        self.LogB_Flush.setText(_translate("MainWindow", "清         空", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_Log), _translate("MainWindow", "Log", None))
        self.comboBox_BM.setItemText(0, _translate("MainWindow", "Base64", None))
        self.comboBox_BM.setItemText(1, _translate("MainWindow", "MD5加密", None))
        self.comboBox_BM.setItemText(2, _translate("MainWindow", "URI编解码", None))
        self.comboBox_BM.setItemText(3, _translate("MainWindow", "Hex<->String", None))
        self.comboBox_BM.setItemText(4, _translate("MainWindow", "Hex ->ASCII", None))
    
        self.label.setText(_translate("MainWindow", "原文:", None))
        self.label_2.setText(_translate("MainWindow", "解码结果:", None))
        self.comboBox.setItemText(0, _translate("MainWindow", "UTF-8", None))
        self.comboBox.setItemText(1, _translate("MainWindow", "GB2312", None))
        self.comboBox.setItemText(2, _translate("MainWindow", "GBK", None))        
        self.BBM_BM.setText(_translate("MainWindow", "编码", None))
        self.BBM_JM.setText(_translate("MainWindow", "解码", None))
        self.BBM_JSQ.setText(_translate("MainWindow", "计算器", None))
        self.BBM_Change.setText(_translate("MainWindow", "上下互换", None))
        self.BBM_Flush.setText(_translate("MainWindow", "清空", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_Bjm), _translate("MainWindow", "编解码", None))
        self.tabWidget_LY.setTabText(self.tabWidget_LY.indexOf(self.tab_2), _translate("MainWindow", "插入文本", None))
        self.tabWidget_LY.setTabText(self.tabWidget_LY.indexOf(self.tab_3), _translate("MainWindow", "源代码", None))
        self.B_YL_PY.setText(_translate("MainWindow", "生成PY", None))
        self.B_YL_reset.setText(_translate("MainWindow", "重置", None))
        self.B_YL_open.setText(_translate("MainWindow", "打开", None))
        self.B_YL_flush.setText(_translate("MainWindow", "插入文本", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_LY), _translate("MainWindow", "生成用例", None))
    
        self.progressBar.setFormat(_translate("MainWindow", "第 %v 次", None))
        self.Label_Num.setText(_translate("MainWindow", "发送次数", None))
        self.B_test.setText(_translate("MainWindow", "测试通讯", None))
        self.B_pause.setText(_translate("MainWindow", "暂停", None))
        self.B_stop.setText(_translate("MainWindow", "停止", None))
        self.Show_Status.setText(_translate("MainWindow", "状态：未运行", None))
        self.CheckBox_Enter.setText(_translate("MainWindow", "使用\\r\\n", None))
        self.Label_Port.setText(_translate("MainWindow", "端口", None))
        self.Label_Time.setText(_translate("MainWindow", "间隔时间", None))
        self.Label_S.setText(_translate("MainWindow", "S", None))
        self.B_reset.setText(_translate("MainWindow", "重置", None))
    
#----------- 主界面窗口函数 ------------------------------------------  
    def Init_User(self):
        #用户初始化整个程序
        global G_Singal
        global G_Ori_Data
        global G_Code
        global G_ScanFlag
        global G_Raw
        G_Raw=0
        G_Singal=0
        G_ScanFlag=2
        G_Ori_Data[1]=""
        G_Ori_Data[0]="N"
        self.BigFileName=""             #读文件
        self.progressBar.setMaximum(1)
        self.progressBar.setMinimum(0)          #初始化设置进度条
        self.progressBar.setValue(0)
        self.radio_wireshark.setChecked(True)
        self.Target_Ip.setText("")
        self.Target_Port.setValue(0)
        self.Username.setText("admin")
        self.B_pause.setEnabled(False)
        self.B_stop.setEnabled(False)
        self.B_send.setEnabled(False)
        self.B_test.setEnabled(True)        
        self.Username.setEnabled(False)         #用户名框
        self.Password.setEnabled(False)         #密码框
        self.B_send.setEnabled(False)           #发送按钮
        self.SpinBox_Num.setValue(1)            #发送次数
        self.SpinBox_Time.setValue(0.0)         #发送时间
        self.Edit_data.setText("")              #数据输入窗口
        self.Show_Log.setText("")               #Log输出窗口
        self.comboBox_Rz.setCurrentIndex(0)     #认证下拉列表框
        self.comboBox_raw.setCurrentIndex(0)    #数据解码列表框
        self.textEdit_Data.setText("")          #编解码原文输入框
        self.textEdit_Res.setText("")           #编解码结果显示框
        self.CheckBox_Enter.setChecked(False)   #使用回车\r\n
        self.Show_Status.setText(u"状态:未运行")
        self.Show_Status.setAutoFillBackground(True)
        #-----设置背景颜色
        p=QPalette()
        p.setColor(QPalette.Window,QColor(240,240,240))
        self.Show_Status.setPalette(p)
        #-------------------------
        self.plainTextEdit_txt.setPlainText("")
        self.plainTextEdit_code.setPlainText(G_Code)
        self.plainTextEdit_left.setPlainText("")
        self.plainTextEdit_right.setPlainText("")
        self.Scan_port_1.setText("80,8000")

        self.SpinBox_Timeout.setValue(0.5)
        self.Scan_IP.setText("")

    def f_send(self):
        global G_Singal
        num=self.SpinBox_Num.value()
        self.progressBar.setMaximum(num)
        stime=self.SpinBox_Time.value()
        chg=self.RadioStatus()
        ip=self.Target_Ip.text()
        port=self.Target_Port.value()
        data=""
        user=""
        pwd=""
        #wireshark 数据报文
        ExceptChoose=(6,7) #6,7选项不进行数据检查
        if self.radio_wireshark.isChecked() and self.comboBox_Rz.currentIndex() not in ExceptChoose:        #发送wireshark数据流,读文件情况
            data=self.Ret16LX()#获取数据流
            if data==True:
                return
            try:
                data=self.h2bin(data)
            except:
                self.alertBox(u"数据格式不标准！请使用WireShark数据流!")
                return
        elif self.radio_16.isChecked() and self.comboBox_Rz.currentIndex() not in ExceptChoose:             #发送16进制数据流
            try:
                data=self.Edit_data.toPlainText()
                data=self.h2bin(data)
            except:
                self.alertBox(u"数据格式不标准！请使用纯16进制数据流!")
                return            
        elif self.radio_text.isChecked() and self.comboBox_Rz.currentIndex() not in ExceptChoose:           #发送明文数据流
            try:
                data=self.Edit_data.toPlainText()
                data=unicode(data.toUtf8(),'utf8','ignore')        
                if self.comboBox_Rz.currentIndex()==1 or self.comboBox_Rz.currentIndex()==2:              #自动添加认证信息
                    user=self.Username.text()
                    pwd=self.Password.text()
                    user=unicode(user.toUtf8(),'utf8','ignore')
                    pwd=unicode(pwd.toUtf8(),'utf8','ignore')
                    user=user.strip()
                    pwd=pwd.strip()
                    if user=="" or pwd=="":
                        self.alertBox(u"用户名密码不能为空!")
                        return
                    if self.comboBox_Rz.currentIndex()==1:          #Basic认证
                        if "$basic$" not in data:
                            self.alertBox(u"未检测到 $basic$ 占位符!请输入占位符!")
                            return
                        u_and_p=user+":"+pwd
                        basic_auth=base64.b64encode(u_and_p)
                        auth="Authorization: Basic "+basic_auth
                        data=data.replace("$basic$",auth)           #使用占位符替换认证
                if self.CheckBox_Enter.isChecked():
                    data=data.replace("\n","\r\n")
            except:
                self.alertBox(u"数据解析异常！")
                return 


        self.B_pause.setEnabled(True)
        self.B_stop.setEnabled(True)  
        G_Singal=1
        self.tabWidget.setCurrentIndex(1)           #切换标签页面

        if self.comboBox_Rz.currentIndex()==3:          #UDP发送报文并接收消息  
            self.setStatus(1)       
            self.thread.sender(ip,port,data,num,stime,"UDP-Recv",user,pwd)
            return 
        elif self.comboBox_Rz.currentIndex()==4:          #UDP发送报文不接收消息   
            self.setStatus(1)    
            self.thread.sender(ip,port,data,num,stime,"UDP-Send",user,pwd)
            return 
        elif self.comboBox_Rz.currentIndex()==5:          #UDP组播报文接收消息   
            self.setStatus(1)        
            self.thread.sender(ip,port,data,num,stime,"UDP-Multicast",user,pwd)
            return  
        elif self.comboBox_Rz.currentIndex()==6:          #TCP随机报文不接收消息   
            self.setStatus(1)
            self.thread.sender(ip,port,data,num,stime,"TCP-Random",user,pwd)
            return            
        elif self.comboBox_Rz.currentIndex()==7:          #读取文件流发送
            if self.BigFileName=="":
                self.alertBox(u"文件名为空！禁止发包！")
                return
            self.progressBar.setValue(0)
            self.progressBar.setMaximum(10000)
            self.thread.SetBigFile(ip,port,self.BigFileName,num,stime)
            self.thread.start()
            return
        else:
            self.progressBar.setValue(0)
            self.thread.sender(ip,port,data,num,stime)
            return



    def h2bin(self,x):#进制转换
        try:
            x=unicode(x.toUtf8(),'utf8','ignore')
        except:
            pass
        x=x.strip()
        return x.replace(' ', '').replace('\n', '').decode('hex')



    #获取发送数据流的类型
    def RadioStatus(self):
        if self.radio_wireshark.isChecked():
            return 1
        elif self.radio_text.isChecked():
            return 2
        elif self.radio_16.isChecked():
            return 3    

    def f_pause(self):
        global G_Singal
        if G_Singal==1:     #1运行
            G_Singal=2
        elif G_Singal==2:   #2暂停
            G_Singal=1


    def f_stop(self):
        global G_Singal
        G_Singal=0


    def f_test(self):
        ip=self.Target_Ip.text()
        port=self.Target_Port.value()
        soc=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            soc.settimeout(3)
            soc.connect((ip,port))
            self.alertBox(u"测试通过，通讯正常! ")
            self.B_send.setEnabled(True)           #发送按钮
        except:
            self.B_send.setEnabled(False)           #发送按钮
            self.alertBox(u"连接失败，请检查IP及端口是否正确!")




    def f_reset(self):
        self.Init_User()
        self.alertBox(u"重置成功！")


#----------- 数据窗口函数 ------------------------------------------   
    def Df_DB_16(self):
        global G_Ori_Data
        if (self.CheckData()):        #检查数据格式
            return                
        if G_Ori_Data[0]=="N":
            G_Ori_Data[1]=self.Edit_data.toPlainText()             #获取数据框中的内容
            G_Ori_Data[0]="Y"
        data=G_Ori_Data[1]
        line=data.split("\n")
        tmp16=""
        for l in line:
            tmp16+=l[10:58]
            tmp16+="\n"
        self.Edit_data.setTextColor(QtGui.QColor(240,60,234))
        self.Edit_data.setText(tmp16)



    def Df_DB_16LX(self):
        global G_Ori_Data
        if (self.CheckData()):        #检查数据格式
            return         
        if G_Ori_Data[0]=="N":
            G_Ori_Data[1]=self.Edit_data.toPlainText()             #获取数据框中的内容
            G_Ori_Data[0]="Y"
        data=G_Ori_Data[1]
        line=data.split("\n")
        tmp16=""
        for l in line:
            tmp16+=l[10:58]
        tmp16=tmp16.replace(" ","")
        self.Edit_data.setTextColor(QtGui.QColor(240,60,60))
        self.Edit_data.setText(tmp16)
        return tmp16

    def Ret16LX(self):
        if (self.CheckData()):                        #检查数据格式
            return True         
        data=self.Edit_data.toPlainText()             #获取数据框中的内容
        line=data.split("\n")
        tmp16=""
        for l in line:
            tmp16+=l[10:58]
        tmp16=tmp16.replace(" ","")
        return tmp16    


    def Df_DB_8(self):
        global G_Ori_Data
        if (self.CheckData()):        #检查数据格式
            return        
        if G_Ori_Data[0]=="N":
            G_Ori_Data[1]=self.Edit_data.toPlainText()             #获取数据框中的内容
            G_Ori_Data[0]="Y"

        data=G_Ori_Data[1]
        line=data.split("\n")
        tmp16=""
        for l in line:
            tmp16+=l[10:58]
            tmp16+="\n"
        tmp8=""
        line=tmp16.split("\n")
        for t in line:
            j=t.replace("  ","\n")
            tmp8+=j
            tmp8+="\n"
        self.Edit_data.setTextColor(QtGui.QColor(60,126,240))
        self.Edit_data.setText(tmp8)




    def Df_DB_Flush(self):
        global G_Ori_Data
        G_Ori_Data[0]="N"
        G_Ori_Data[1]=""
        self.Edit_data.setText("")


    def Df_DB_Initdata(self):
        global G_Ori_Data
        if G_Ori_Data[0]=="Y":
            self.Edit_data.setTextColor(QtGui.QColor(0,0,0))
            self.Edit_data.setText(G_Ori_Data[1])
        G_Ori_Data[0]="N"
        G_Ori_Data[1]=""

    def Df_comboBox_Rz(self,w):
        if w==0 or w==6:
            self.Username.setEnabled(False)
            self.Password.setEnabled(False)
            self.B_test.setEnabled(True)
        elif w==1:
            self.alertBox(u"请在需要添加认证的地方使用以下占位符:\n\t$basic$")
            self.Username.setEnabled(True)
            self.Password.setEnabled(True) 
            self.B_test.setEnabled(True)
        elif w==2:
            #self.alertBox(u"请在需要添加认证的地方使用以下占位符:\n\t$digest$")
            self.alertBox(u"暂不支持Digest认证...")
            self.Username.setEnabled(True)
            self.Password.setEnabled(True)
            self.B_test.setEnabled(True)  
        elif w==3 or w==4 or w==5:
            self.B_send.setEnabled(True)
            self.B_test.setEnabled(False)
        elif w==7:
            self.BigFileName=QtGui.QFileDialog.getOpenFileName(self,"Big File")
            if self.BigFileName=="":
                self.alertBox(u"读取文件失败!")
                self.comboBox_Rz.setCurrentIndex(0)
                return
            self.tabWidget.setCurrentIndex(1)           #切换标签页面
            self.Show_Log.insertHtml(u"<font color=red >Notes:建议文件内容为WireShark流中的Hex Dump格式！</font>\n")
            self.Show_Log.insertPlainText(u"\n读取文件成功!\n")
            self.Show_Log.insertPlainText(self.BigFileName)
            self.Show_Log.insertPlainText(u"\n\n")

    def CheckData(self):#检查数据格式的合法性
        global G_Ori_Data
        txt=self.Edit_data.toPlainText()             #获取数据框中的内容 
        pattern=re.compile(r"^\S{8}[ ]{2}\S{2}")
        line=txt.split("\n")
        for l in line:
            if len(l)<60:
                self.alertBox(u"处理失败!数据格式不标准！")
                return True            
            if l[58]!=" ":
                self.alertBox(u"处理失败!数据格式不标准！")
                return True                
            if pattern.match(l)==None:
                self.alertBox(u"处理失败!数据格式不标准！")
                return True
        return False

#------------- Log窗口函数 ----------------------------------------  

    def Lf_DB_Flush(self):
        self.Show_Log.setText("")


    def Lf_showlog(self,txt):
        txt="\n"+txt+"\n"
        #-------滚动条自动向下
        cu=self.Show_Log.textCursor()
        cu.movePosition(QtGui.QTextCursor.EndOfLine)
        self.Show_Log.setTextCursor(cu)
        if "Send Num:[ " in txt or "<font color=red><br>[" in txt:
            self.Show_Log.insertHtml(txt)
        else:
            self.Show_Log.insertPlainText(txt)

        cu=self.Show_Log.textCursor()
        cu.movePosition(QtGui.QTextCursor.EndOfLine)
        self.Show_Log.setTextCursor(cu)        



    def setJD(self,count):
        self.progressBar.setValue(count)

    def setStatus(self,stat):
        global G_Light
        if stat==1:
            self.Show_Status.setText(u"状态:正在发送")
            p=QPalette()
            p.setColor(QPalette.Window,QColor(240,240,240))
            self.Show_Status.setPalette(p)            
        elif stat==2:
            self.Show_Status.setText(u"状态:通讯异常")
            p=QPalette()
            if G_Light==0:
                p.setColor(QPalette.Window,QColor(240,22,22))
                G_Light=1
            else:
                p.setColor(QPalette.Window,QColor(247,255,0))
                G_Light=0
            self.Show_Status.setPalette(p)
        elif stat==3:
            self.Show_Status.setText(u"状态:发送完成")

        elif stat==10:
            self.Show_Status.setText(u"状态:暂停") 

        elif stat==20:        
            p=QPalette()
            p.setColor(QPalette.Window,QColor(240,240,240))
            self.Show_Status.setPalette(p)
            self.Show_Status.setText(u"状态:手动停止") 

        elif stat==4:
            self.Show_Status.setText(u"异常:含特殊编码") 
            p=QPalette()
            p.setColor(QPalette.Window,QColor(33,232,199))
            self.Show_Status.setPalette(p)
#------------- 编解码窗口函数 ----------------------------------------        

    def Bf_comboBox_BM(self,w):
        if w==1:
            self.BBM_JM.setEnabled(False) 
            self.BBM_BM.setEnabled(True)
        elif w==4:
            self.BBM_BM.setEnabled(False)
            self.BBM_JM.setEnabled(True)
        else:
            self.BBM_JM.setEnabled(True)
            self.BBM_BM.setEnabled(True)



    def Bf_BBM_BM(self):
        data=self.textEdit_Data.toPlainText()
        data=unicode(data.toUtf8(),'utf8','ignore')
        data=data.strip()
        if self.comboBox_BM.currentIndex()==0:                              #Base64加密解密
            try:
                self.textEdit_Res.setText(self.Base64("encode",data))
            except:
                self.alertBox(u"编码失败!")
            return
        elif self.comboBox_BM.currentIndex()==1:                            #MD5加密
            try:
                self.textEdit_Res.setText(self.cMd5(data))
            except:
                self.alertBox(u"编码失败!")
            return
        elif self.comboBox_BM.currentIndex()==2:                            #URI编码解码
            try:
                self.textEdit_Res.setText(self.Uri("encode",data))
            except:
                self.alertBox(u"编码失败!")
            return                   
        elif self.comboBox_BM.currentIndex()==3:                            #char-》16
            s=self.toHex(data)
            self.textEdit_Res.setText(s)



    def toHex(self,s):
        if self.comboBox.currentIndex()==0:
            return binascii.b2a_hex(s) 
        elif self.comboBox.currentIndex()==1:
            return binascii.b2a_hex(s.decode("utf8").encode("gb2312"))        
        elif self.comboBox.currentIndex()==2:
            return binascii.b2a_hex(s.decode("utf8").encode("gbk"))


    def Base64(self,flag,data):#base64加解密
        if flag=="encode":
            return base64.b64encode(str(data))
        elif flag=="decode":
            return base64.decodestring(str(data))


    def cMd5(self,data):
        if len(data)==0:
            return ""
        mdf5=md5.new()
        mdf5.update(data)
        return mdf5.hexdigest() 

    def Uri(self,flag,data):
        if flag=="encode":
            return urllib.quote(str(data))
        elif flag=="decode":
            return urllib.unquote(str(data))     


    def Bf_BBM_JM(self):
        data=self.textEdit_Data.toPlainText()
        data=unicode(data.toUtf8(),'utf8','ignore')
        data=data.strip()
        if self.comboBox_BM.currentIndex()==0:                              #Base64加密解密
            s=self.getBMcode(self.Base64("decode",data))
            try:
                self.textEdit_Res.setText(s)
            except:
                self.alertBox(u"解码失败!")
                return                 
        elif self.comboBox_BM.currentIndex()==1:                            #MD5解密
            pass
        elif self.comboBox_BM.currentIndex()==2:                            #URI编码解码
            s=self.getBMcode(self.Uri("decode",data))
            try:
                self.textEdit_Res.setText(s)
            except:
                self.alertBox(u"解码失败!")
                return       
        elif self.comboBox_BM.currentIndex()==3:                            #Hex-》string
            try:
                s=self.getBMcode(self.h2bin(data))
            except:
                self.alertBox(u"16进制流不标准，转换失败!")
                return
            try:
                self.textEdit_Res.setText(s) 
            except:
                self.alertBox(u"解码失败!")
        elif self.comboBox_BM.currentIndex()==4:                            #Hex-》char
            try:
                s=self.HexToChr(self.h2bin(data))
            except:
                self.alertBox(u"16进制流不标准，转换失败!")
                return
            try:
                self.textEdit_Res.setText(s) 
            except:
                self.alertBox(u"解码失败!")                


    def HexToChr(self,s):
        return self.thread.Raw_pack(s)




    def getBMcode(self,s):    #用来返回各种不同类型的编码结果
        if self.comboBox.currentIndex()==0:     #utf8
            try:
                s=s.decode('utf8')
            except:
                s=u"编码不正确，解码失败!"
            return s
        elif self.comboBox.currentIndex()==1:   #gb2312
            try:
                s=s.decode('gb2312')
            except:
                s=u"编码不正确，解码失败!"
            return s
        elif self.comboBox.currentIndex()==2:   #gbk
            try:
                s=s.decode('gbk')
            except:
                s=u"编码不正确，解码失败!" 
            return s           

    def Bf_BBM_Change(self):
        tmp=self.textEdit_Data.toPlainText()
        self.textEdit_Data.setText(self.textEdit_Res.toPlainText())
        self.textEdit_Res.setText(tmp)

    def Bf_BBM_Flush(self):
        self.textEdit_Data.setText(u"")
        self.textEdit_Res.setText(u"")        

    def Bf_BBM_JSQ(self):
        pass
        #win32api.ShellExecute(0, 'open', 'calc.exe', '','',0)

#----------------------------------------------------
    def Bf_LY_Make_py(self):
        code=self.plainTextEdit_code.toPlainText()
        code=unicode(code.toUtf8(),'utf8','ignore')
        if "$txt$" in code:
            self.alertBox(u"请先插入要填充的内容!")
            return
        ti=time.asctime()
        ti=ti.replace(" ","_").replace(":",".")  
        fname="Check_%s.py" % ti
        fp=open(fname,"w")
        fp.write(code)
        fp.close()
        self.alertBox(u"生成用例成功!")



    def Bf_LY_reset(self):
        self.plainTextEdit_txt.setPlainText("")
        self.plainTextEdit_code.setPlainText(G_Code)

    def Bf_LY_open(self):
        pp=os.getcwd()
        os.popen("explorer.exe %s" % pp)




    def Bf_LY_reflush(self):
        global G_Code
        data=self.plainTextEdit_txt.toPlainText()
        data=unicode(data.toUtf8(),'utf8','ignore')
        code=G_Code
        data="\"\"\"%s\"\"\"" % data
        code=code.replace("$txt$",data)
        self.plainTextEdit_code.setPlainText(code)
        self.tabWidget_LY.setCurrentIndex(1)
    #--------------------------------------------------------------------------------------

    def Port_scan(self):
        global G_ScanFlag
        if G_ScanFlag==1:
            self.alertBox(u"请等待本次扫描结束！或重置强制退出！")
            return
        scan_TimeOut=self.SpinBox_Timeout.value()
        Tag_Ip=self.get_IP_list()
        if Tag_Ip==False:
            self.alertBox(u"扫描的IP不正确!\nEg: 10.2.1.0/24")
            return

        try:
            Tag_Port=self.get_Sport()
        except:
            self.alertBox(u"扫描端口不正确!\nEg:\t80\nEg1:\t21-23 \nEg2:\t80,8000")
            return
        if G_ScanFlag==0 or G_ScanFlag==2:
            self.plainTextEdit_left.setPlainText("")
            self.plainTextEdit_right.setPlainText("")
            G_ScanFlag=0
            self.thread.GetIpScan(Tag_Ip,Tag_Port,scan_TimeOut)
            self.thread.start()

    def Df_comboBox_Raw(self,w):
        global G_Raw    #返回报文状态
        if w==0:
            G_Raw=0
        elif w==1:
            G_Raw=1
        elif w==2:
            G_Raw=2    


    def write_ip(self,Left,Right):

        #-------滚动条自动向下
        cu=self.plainTextEdit_left.textCursor()
        cu.movePosition(QtGui.QTextCursor.EndOfWord)
        self.plainTextEdit_left.setTextCursor(cu)
        self.plainTextEdit_left.insertPlainText(Left)


        #-------滚动条自动向下
        cu=self.plainTextEdit_right.textCursor()
        cu.movePosition(QtGui.QTextCursor.EndOfWord)
        self.plainTextEdit_right.setTextCursor(cu)  
        self.plainTextEdit_right.insertPlainText(Right)

        if Left==u"扫描结束!":
            self.B_ScanPort.setText(u"扫描")

    def get_IP_list(self):
        ip=self.Scan_IP.text()
        ip=unicode(ip.toUtf8(),'utf8','ignore')
        try:
            IP_List=IP(ip)
        except:
            IP_List=False
        return IP_List

    def get_Sport(self):
        port=[]
        port_left=self.Scan_port_1.text()
        port_left=unicode(port_left.toUtf8(),'utf8','ignore')
        if "," in port_left:
            port=port_left.split(",")
            for i in range(len(port)):
                port[i]=int(port[i])
            return port
        elif "-" in port_left:
            p=port_left.split("-")
            port_1=int(p[0])
            port_2=int(p[1])
            for p in range(port_1,port_2+1):
                port.append(p)          
            return port
        else:
            port.append(int(port_left.strip()))
            return port


    def alertBox(self,txt):
        QtGui.QMessageBox.information(self,u"提示",txt ) 
        return
    
    
    
def main():
    app=QtGui.QApplication(sys.argv)
    win=Ui_MainWindow()
    win.show()
    sys.exit(app.exec_())

main()