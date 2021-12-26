# 实验五 基于scapy编写端口扫描器

## 一、实验目的

掌握网络扫描之端口状态的探测原理

## 二、实验环境

- python

- scapy

- 攻击者主机（attacker-kali)
  - 172.16.111.101
  
- 受害者主机（victim-kali-1)
  - 172.16.111.108
  
- 网关（Debian-gw)
  - 172.16.111.1

- 网络拓扑：

  ![](C:\Users\111\Desktop\chap0x05\IMG5\net.png)

## 三、实验要求

- 禁止探测互联网上的IP ，严格遵守互联网安全相关法规   ✔
- 完成以下扫描技术的编程实现  ✔
  - TCP connet scan/ TCP stealth 
  - TCP Xmas scan/ TCP fin scan/ TCP null scan 
  - UDP scan
- 上述每种扫描技术实现测试均需要测试 端口状态为：**开放**、**关闭**、和**过滤** 状态时的程序执行结果  ✔
- 提供每一次扫描测试的抓包结果并分析与课本中扫描方法原理是否相符？如果不同，请分析原因 ✔
- 在实验报告中详细说明实验网络环境拓扑、被测试IP端口状态是如何模拟的 ✔
- （可选）复刻nmap的上述扫描技术实现的命令行参数开关

## 四、实验准备

### 关于scapy操作

- 指令

  ```
  # 导入
  from scapy.all import *
  # 查看
  pkt = IP(dst="")
  ls(pkt)
  pkt.show()
  summary(pkt)
  # 发送数据包
  # 发送第三层数据包，但不收到返回结果
  send(pkt)
  # 发送第三层数据包，返回接收到相应的数据包和未接受到响应的数据包
  sr(pkt)
  # 发送第三层数据包，返回接收到响应的数据包
  srl(pkt)
  # 发送第二层数据包
  sendp(pkt)
  # 发送第二层数据包，等待响应
  srp(pkt)
  # 发送第二层数据包，返回响应的数据包
  srpl(pkt)
  # 监听网卡
  sniff(iface="wlan1",count=100,filter="tcp")
  ```

### 关于端口操作

- 端口关闭状态：端口关闭监听，防火墙关闭

  ```
  # 受害者主机安装ufw
  apt-get install ufw
  # 关闭防火墙
  ufw disable
  # 关闭特定端口
  systemctl stop apache2
  systemctl stop dnsmasq
  ```

  - ufw（简单防火墙Uncomplicated FireWall）真正地简化了 iptables，它从出现的这几年，已经成为 Ubuntu 和 Debian 等系统上的默认防火墙。
  - apache2: 80端口，基于TCP
  - dnsmasq: 53端口，基于UDP

- 端口开启状态：端口开启监听，防火墙仍然关闭

  ```
  # 开启80端口
  systemctl start apache2
  # 开启53端口
  systemctl start dnsmasq
  ```

- 端口过滤状态：端口开启监听，防火墙开启

  ```
  # 开启防火墙
  sudo ufw enable
  # 开启80端口监听
  ufw enable && ufw deny 80/tcp
  # 开启53端口监听
  ufw enable && ufw deny 53/udp
  ```

- dnsmasq相关

  ```
  # 安装dnsmasq
  sudo apt-get update
  sudo apt-get install dnsmasq
  # 启动dnsmasq
  systemctl start dnsmasq
  # 查看状态
  systemctl status dnsmasq
  # 关闭dnsmasq
  systemctl stop dnsmasq
  ```

## 五、实验过程

### TCP connet scan/ TCP stealth 

- 初始状态

  ![](C:\Users\111\Desktop\chap0x05\IMG5\TCP-初始状态.png)

  **TCP connect scan** 首先发送一个SYN数据包到目标主机的特定端口，接着我们可以通过接受报的情况对端口状态进行判断：如果接收到的是一个SYN/ACK数据包，则说明端口是开放状态的；如果接受到的是一个RST/ACK数据包，通常意味着端口是关闭的并且链接将会被重置；而如果目标主机没有任何响应则意味着目标主机的端口处于过滤状态；若接收到SYN/ACK数据包，及检测到端口是开启状态的，便发送一个ACK确认包到目标主机，这样便完成三次握手。

- code**(TCP-connect-scan.py)**

  ```python
  from scapy.all import *
  
  def tcpconnect(dst_ip, dst_port, timeout=10):
      pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="S"),timeout=timeout)
      # 无响应意味着目标主机的端口处于过滤状态
      if pkts is None:
          print("Filtered")
      elif(pkts.haslayer(TCP)):
          # 0x012:(SYN,ACK)包证明端口开放
          if(pkts.getlayer(TCP).flags == 0x12):
              #发送ACK确认包
              send_rst = sr(IP(dst=dst_ip)/TCP(dport=dst_port,flags="AR"),timeout=timeout)
              print("Open")
          # 0x014:(RST,ACK)包证明端口关闭
          elif (pkts.getlayer(TCP).flags == 0x14):   
              print("Closed")
  
  # 连接靶机
  tcpconnect('172.16.111.108', 80)
  ```

#### CLOSED

- 在靶机执行`sudo ufw disable`&`systemctl stop apache2`使其处于关闭状态

  ![TCP-connect-closed](C:\Users\111\Desktop\chap0x05\IMG5\TCP-connect-closed.png)

- 将TCP-connect-scan.py 文件拖放到攻击者主机，并执行

  - 设备-->共享粘贴板-->双向
  - 设备-->拖放-->双向

  ![TCP-connect-closed-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\TCP-connect-closed-sudo py.png)

- 在靶机中wireshark抓包情况

  ![TCP-connect-closed-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\TCP-connect-closed-wireshark.png)

- nmap复刻：`nmap -sT -p 80 172.16.111.108`

  ![TCP-connect-closed-nmap](C:\Users\111\Desktop\chap0x05\IMG5\TCP-connect-closed-nmap.png)

#### OPEN

- 受害者主机：`systemctl start apache2`

  ![TCP-connect-open](C:\Users\111\Desktop\chap0x05\IMG5\TCP-connect-open.png)

- 攻击者主机执行.py文件

  ![TCP-connect-open-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\TCP-connect-open-sudo py.png)

- 靶机抓包情况

  ![](C:\Users\111\Desktop\chap0x05\IMG5\TCP-connect-open-wireshark.png)

- nmap:

  ![](C:\Users\111\Desktop\chap0x05\IMG5\TCP-connect-open-nmap.png)

#### FILTERED

- `sudo ufw enable && sudo ufw deny 80/tcp`

  ![](C:\Users\111\Desktop\chap0x05\IMG5\TCP-connect-filter.png)

- 受害者主机执行.py文件

  ![](C:\Users\111\Desktop\chap0x05\IMG5\TCP-connect-filter-sudo py.png)

- 靶机抓包情况

  ![](C:\Users\111\Desktop\chap0x05\IMG5\TCP-connect-filter-wireshark.png)

- nmap

  ![](C:\Users\111\Desktop\chap0x05\IMG5\TCP-connect-filter-nmap.png)

### TCP stealth scan

- **TCP stealth scan**发送一个SYN包启动三次握手连接机制，并等待响应。如果收到一个SYN/ACK包表示目标端口是开放的；如果接收到一个RST/ACK包表示目标端口是关闭的；如果端口为过滤状态则没有响应。当得到的是一个SYN/ACK包时通过发送一个RST包立即解除连接。

- code**(TCP-stealth-scan.py)**

  ```python
  from scapy.all import *
  
  
  def tcpstealthscan(dst_ip, dst_port, timeout=10):
      pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="S"), timeout=10)
      if (pkts is None):
          print("Filtered")
      elif(pkts.haslayer(TCP)):
          if(pkts.getlayer(TCP).flags == 0x12):
              send_rst = sr(IP(dst=dst_ip) /
                            TCP(dport=dst_port, flags="R"), timeout=10)
              print("Open")
          elif (pkts.getlayer(TCP).flags == 0x14):
              print("Closed")
          elif(pkts.haslayer(ICMP)):
              if(int(pkts.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                  print("Filtered")
  
  
  tcpstealthscan('172.16.111.108', 80)
  ```

#### CLOSED

- 在靶机执行`sudo ufw disable`&`systemctl stop apache2`使其处于关闭状态

  ![](C:\Users\111\Desktop\chap0x05\IMG5\TCP-stealth-closed.png)

- 将TCP-stealth-scan.py 文件拖放到攻击者主机，并执行

  ![](C:\Users\111\Desktop\chap0x05\IMG5\TCP-stealth-closed-sudo py.png)

- 靶机查看抓包情况

  ![](C:\Users\111\Desktop\chap0x05\IMG5\TCP-stealth-closed-wireshark.png)

- nmap复刻: `sudo nmap -sS -p 80 172.16.111.108`

  ![](C:\Users\111\Desktop\chap0x05\IMG5\TCP-stealth-closed-nmap.png)

#### OPEN

- 在靶机执行`systemctl start apache2`

  ![](C:\Users\111\Desktop\chap0x05\IMG5\TCP-stealth-open.png)

- 将TCP-stealth-scan.py 文件拖放到攻击者主机，并执行

  ![TCP-stealth-open-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\TCP-stealth-open-sudo py.png)

- 靶机查看抓包情况

  ![TCP-stealth-open-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\TCP-stealth-open-wireshark.png)

- nmap复刻

  ![TCP-stealth-open-nmap](C:\Users\111\Desktop\chap0x05\IMG5\TCP-stealth-open-nmap.png)

#### FILTERED

- 在靶机执行`sudo ufw enable && sudo ufw deny 80/tcp`

  ![TCP-stealth-filtered](C:\Users\111\Desktop\chap0x05\IMG5\TCP-stealth-filtered.png)

- 将TCP-stealth-scan.py 文件拖放到攻击者主机，并执行

  ![TCP-stealth-filtered-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\TCP-stealth-filtered-sudo py.png)

- 靶机查看抓包情况

  ![TCP-stealth-filtered-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\TCP-stealth-filtered-wireshark.png)

- nmap复刻

  ![TCP-stealth-filtered-nmap](C:\Users\111\Desktop\chap0x05\IMG5\TCP-stealth-filtered-nmap.png)

### TCP Xmas scan

- **TCP Xmas scan**发送一个TCP包，并对TCP报文头FIN,URG,PUSH标记进行设置。若端口关闭则响应RST报文；开放或过滤状态下的端口无任何响应。

- code**(TCP-Xmas-scan.py)**

  ```python
  from scapy.all import *
  
  def Xmasscan(dst_ip, dst_port, timeout=10):
      pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="FPU"), timeout=10)
      if (pkts is None):
          print("Open|Filtered")
      elif(pkts.haslayer(TCP)):
          if(pkts.getlayer(TCP).flags == 0x14):
              print("Closed")
      elif(pkts.haslayer(ICMP)):
          if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
              print("Filtered")
  
  
  Xmasscan('172.16.111.108', 80)
  ```

#### CLOSED

- 在靶机执行`sudo ufw disable`&`systemctl stop apache2`使其处于关闭状态

  ![TCP-Xmas-closed](C:\Users\111\Desktop\chap0x05\IMG5\TCP-Xmas-closed.png)

- 将TCP-Xmas-scan.py 文件拖放到攻击者主机，并执行

  ![TCP-Xmas-closed-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\TCP-Xmas-closed-sudo py.png)

- 靶机查看抓包情况

  ![TCP-Xmas-closed-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\TCP-Xmas-closed-wireshark.png)

- nmap复刻: sudo nmap -sX -p 80 172.16.111.108

  ![TCP-Xmas-closed-nmap](C:\Users\111\Desktop\chap0x05\IMG5\TCP-Xmas-closed-nmap.png)

#### OPEN

- 在靶机打开端口：`systemctl start apache2`

  ![TCP-Xmas-open](C:\Users\111\Desktop\chap0x05\IMG5\TCP-Xmas-open.png)

- 将TCP-Xmas-scan.py 文件拖放到攻击者主机，并执行

  ![TCP-Xmas-open-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\TCP-Xmas-open-sudo py.png)

- 靶机查看抓包情况

  ![TCP-Xmas-open-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\TCP-Xmas-open-wireshark.png)

- nmap复刻

  ![TCP-Xmas-open-nmap](C:\Users\111\Desktop\chap0x05\IMG5\TCP-Xmas-open-nmap.png)

#### FILTERED

- 在靶机执行：`sudo ufw enable && sudo ufw deny 80/tcp`

  ![TCP-Xmas-filtered](C:\Users\111\Desktop\chap0x05\IMG5\TCP-Xmas-filtered.png)

- 将TCP-Xmas-scan.py 文件拖放到攻击者主机，并执行

  ![TCP-Xmas-filtered-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\TCP-Xmas-filtered-sudo py.png)

- 靶机查看抓包情况

  ![TCP-Xmas-filtered-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\TCP-Xmas-filtered-wireshark.png)

- nmap复刻

  ![TCP-Xmas-filtered-nmap](C:\Users\111\Desktop\chap0x05\IMG5\TCP-Xmas-filtered-nmap.png)

### TCP fin scan

- **TCP fin scan**发送到的是FIN包,可以直接通过防火墙，，如果端口关闭就会回复RST包，其他则无任何响应。

- code**(TCP-fin-scan.py)**

  ```python
  from scapy.all import *
  
  def finscan(dst_ip, dst_port, timeout=10):
      pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="F"), timeout=10)
      if (pkts is None):
          print("Open|Filtered")
      elif(pkts.haslayer(TCP)):
          if(pkts.getlayer(TCP).flags == 0x14):
              print("Closed")
      elif(pkts.haslayer(ICMP)):
          if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
              print("Filtered")
  
  
  finscan('172.16.111.108', 80)
  ```

#### CLOSED

- 在靶机执行`sudo ufw disable`&`systemctl stop apache2`使其处于关闭状态

  ![TCP-fin-closed](C:\Users\111\Desktop\chap0x05\IMG5\TCP-fin-closed.png)

- 将TCP-fin-scan.py 文件拖放到攻击者主机，并执行

  ![TCP-fin-closed-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\TCP-fin-closed-sudo py.png)

- 靶机查看抓包情况
- ![TCP-fin-closed-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\TCP-fin-closed-wireshark.png)

- nmap复刻: `sudo nmap -sF -p 80 172.16.111.108`

  ![TCP-fin-closed-nmap](C:\Users\111\Desktop\chap0x05\IMG5\TCP-fin-closed-nmap.png)

#### OPEN

- 在靶机执行`systemctl start apache2`

  ![TCP-fin-open](C:\Users\111\Desktop\chap0x05\IMG5\TCP-fin-open.png)

- 将TCP-fin-scan.py 文件拖放到攻击者主机，并执行

  ![TCP-fin-open-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\TCP-fin-open-sudo py.png)

- 靶机查看抓包情况

  ![TCP-fin-open-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\TCP-fin-open-wireshark.png)

- nmap复刻

  ![TCP-fin-open-nmap](C:\Users\111\Desktop\chap0x05\IMG5\TCP-fin-open-nmap.png)

#### FILTERED

- 在靶机执行`sudo ufw enable && sudo ufw deny 80/tcp`

  ![TCP-fin-filtered](C:\Users\111\Desktop\chap0x05\IMG5\TCP-fin-filtered.png)

- 将TCP-fin-scan.py 文件拖放到攻击者主机，并执行

  ![TCP-fin-filtered-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\TCP-fin-filtered-sudo py.png)

- 靶机查看抓包情况

  ![TCP-fin-filtered-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\TCP-fin-filtered-wireshark.png)

- nmap复刻

  ![TCP-fin-filtered-nmap](C:\Users\111\Desktop\chap0x05\IMG5\TCP-fin-filtered-nmap.png)

### TCP null scan

- **TCP null scan**发送一个TCP数据包，关闭所有TCP报文头标记，只有关闭端口会发送RST响应。

- code**(TCP-null-scan.py)**

  ```python
  from scapy.all import *
  
  def nullscan(dst_ip, dst_port, timeout=10):
      pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags=""), timeout=10)
      if (pkts is None):
          print("Open|Filtered")
      elif(pkts.haslayer(TCP)):
          if(pkts.getlayer(TCP).flags == 0x14):
              print("Closed")
      elif(pkts.haslayer(ICMP)):
          if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
              print("Filtered")
  
  nullscan('172.16.111.108', 80)
  ```

#### CLOSED

- 在靶机执行`sudo ufw disable`&`systemctl stop apache2`使其处于关闭状态

  ![TCP-null-closed](C:\Users\111\Desktop\chap0x05\IMG5\TCP-null-closed.png)

- 将TCP-null-scan.py 文件拖放到攻击者主机，并执行

  ![TCP-null-closed-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\TCP-null-closed-sudo py.png)

- 靶机查看抓包情况

  ![TCP-null-closed-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\TCP-null-closed-wireshark.png)

- nmap复刻：`sudo nmap -sN -p 80 172.16.111.108`

  ![TCP-null-closed-nmap](C:\Users\111\Desktop\chap0x05\IMG5\TCP-null-closed-nmap.png)

#### OPEN

- 在靶机执行`systemctl start apache2`

  ![TCP-null-open](C:\Users\111\Desktop\chap0x05\IMG5\TCP-null-open.png)

- 将TCP-null-scan.py 文件拖放到攻击者主机，并执行

  ![TCP-null-open-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\TCP-null-open-sudo py.png)

- 靶机查看抓包情况

  ![TCP-null-open-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\TCP-null-open-wireshark.png)

- nmap复刻

  ![TCP-null-open-nmap](C:\Users\111\Desktop\chap0x05\IMG5\TCP-null-open-nmap.png)

#### FILTERED

- 在靶机执行`sudo ufw enable && sudo ufw deny 80/tcp`

  ![TCP-null-filter](C:\Users\111\Desktop\chap0x05\IMG5\TCP-null-filter.png)

- 将TCP-null-scan.py 文件拖放到攻击者主机，并执行

  ![TCP-null-filter-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\TCP-null-filter-sudo py.png)

- 靶机查看抓包情况

  ![TCP-null-filter-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\TCP-null-filter-wireshark.png)

- nmap复刻

  ![TCP-null-filter-nmap](C:\Users\111\Desktop\chap0x05\IMG5\TCP-null-filter-nmap.png)

### UDP scan

- **UDP scan**多数UDP端口扫描的方法就是像各个被扫描的UDP端口发送零字节的UDP包，如果收到一个ICMP不可达的响应，那么则认为这个端口是关闭的，对于没有回应的端口就是开放的，但如果是目标主机安装有防火墙或其他的过滤数据包的软硬件，我们发出的UDP数据包可能得不到任何回应，我们将会见到被扫描的端口都是开放的。

- code**(TCP-stealth-scan.py)**

  ```python
  from scapy.all import *
  
  def udpscan(dst_ip, dst_port, dst_timeout=10):
      resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port), timeout=dst_timeout)
      if (resp is None):
          print("Open|Filtered")
      elif (resp.haslayer(UDP)):
          print("Open")
      elif(resp.haslayer(ICMP)):
          if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3):
              print("Closed")
          elif(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
              print("Filtered")
          elif(resp.haslayer(IP) and resp.getlayer(IP).proto == IP_PROTOS.udp):
              print("Open")
  
  
  udpscan('172.16.111.108', 53)
  ```

#### CLOSED

- 在靶机执行`sudo ufw disable`&`systemctl stop dnsmasq`使其处于关闭状态

  ![UDP-closed](C:\Users\111\Desktop\chap0x05\IMG5\UDP-closed.png)

- 将UDP-scan.py 文件拖放到攻击者主机，并执行

  ![UDP-closed-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\UDP-closed-sudo py.png)

- 靶机查看抓包情况

  ![UDP-closed-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\UDP-closed-wireshark.png)

- nmap复刻：`sudo nmap -sU -p 53 172.16.111.108`

  ![UDP-closed-nmap](C:\Users\111\Desktop\chap0x05\IMG5\UDP-closed-nmap.png)

#### OPEN

- 在靶机执行`systemctl start dnsmasq`使其处于关闭状态

  ![UDP-open](C:\Users\111\Desktop\chap0x05\IMG5\UDP-open.png)

- 将UDP-scan.py 文件拖放到攻击者主机，并执行

  ![UDP-open-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\UDP-open-sudo py.png)

- 靶机查看抓包情况

  ![UDP-open-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\UDP-open-wireshark.png)

- nmap复刻

  ![UDP-open-nmap](C:\Users\111\Desktop\chap0x05\IMG5\UDP-open-nmap.png)

#### FILTERED

- 在靶机执行`sudo ufw enable && sudo ufw deny 53/udp`

  ![UDP-filtered](C:\Users\111\Desktop\chap0x05\IMG5\UDP-filtered.png)

- 将UDP-scan.py 文件拖放到攻击者主机，并执行

  ![UDP-filtered-sudo py](C:\Users\111\Desktop\chap0x05\IMG5\UDP-filtered-sudo py.png)

- 靶机查看抓包情况

  ![UDP-filtered-wireshark](C:\Users\111\Desktop\chap0x05\IMG5\UDP-filtered-wireshark.png)

- nmap复刻

  ![UDP-filtered-nmap](C:\Users\111\Desktop\chap0x05\IMG5\UDP-filtered-nmap.png)

## 六、参考资料

[电子教材](https://c4pr1c3.gitee.io/cuc-ns/chap0x05/main.html)

[Nmap](https://www.cnblogs.com/bravexz/p/10069371.html)

[dnamasq](https://blog.csdn.net/yanghua1012/article/details/80555487)

[师姐的实验](https://github.com/CUCCS/2020-ns-public-LyuLumos/tree/ch0x05/ch0x05#%E7%AB%AF%E5%8F%A3%E7%8A%B6%E6%80%81%E6%A8%A1%E6%8B%9F)

