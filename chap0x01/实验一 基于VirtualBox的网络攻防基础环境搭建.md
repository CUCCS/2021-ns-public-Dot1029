# 实验一 基于VirtualBox的网络攻防基础环境搭建

## 一、实验目的

1、掌握VirtualBox虚拟机的安装与使用；

2、掌握VirtualBox的虚拟机网络类型和敏锐配置；

3、掌握VirtualBox的虚拟硬盘加载；

## 二、实验环境

VirtualBox虚拟机

靶机（victim)：Windows xp

攻击者主机(attacker)：Kali Rolling

网关(gateway)：Debian Buster

共需六台虚拟机

## 三、实验要求

### 1、虚拟硬盘配置成多重加载，如下效果

![](C:IMG\example1.png)

### 2、搭建满足以下拓扑图所示的网络拓扑

![](C:IMG\example2.png)

### 3、 完成以下网络连通性测试：

靶机可以直接访问攻击者主机

攻击者主机无法直接访问靶机

网关可以直接访问靶机和攻击者主机

靶机的所有上过流量必须经过网关

所有节点都可以访问互联网

### 四、实验步骤

#### 虚拟硬盘配置成多重加载

1、在VietualBox管理器中管理一栏-->虚拟介质管理

2、选中需要修改的硬盘，点击属性-->类型设置为多重加载

3、释放后重新加载

![](C:IMG\kali-vdi.png)

![](C:IMG\debian-vdi.png)

![](C:IMG\windows-vdi.png)

#### 搭建虚拟机网络拓扑

1、配置各虚拟机网络

- **网关debian**需要4块网卡

  网卡一：NAT网络

  网卡二：仅主机（Host-Only）网络

  网卡三：内部网络intnet0 （搭建局域网0）

  网卡四：内部网络intnet1（搭建局域网1）

  ![](C:IMG\gw-set.png)

- **攻击者**需要三块网卡

  网卡一：NAT网络

  网卡二：Host-Only网络

  网卡三：与网卡2不同的Host-Only网络

  ![](C:IMG\attacker-set.png)

- **靶机**需要一块网卡

  网卡一：内部网络

  此时xp-1和kali-1选择inthet0；xp-2和debain-2选择intnet1

  ![](C:IMG\debain2-set.png)

  ![](C:IMG\xp2-set.png)

  ![](C:IMG\xp1-set.png)

  

  ![](C:IMG\kali1-set.png)

  **各个虚拟机IP地址**

  | 虚拟机节点      | ip地址         |
  | --------------- | -------------- |
  | victim-xp-1     | 172.16.111.101 |
  | victim-kali-1   | 172.16.111.130 |
  | victim-xp-2     | 172.16.222.135 |
  | victim-debain-2 | 172.16.222.149 |
  | attacker-kali   | 10.0.2.4       |


#### 连通性测试

- 靶机可以直接访问攻击者主机

  局域网intnet0内靶机可以访问攻击者主机

  ![](C:IMG\ping-xp1-attacker.png)

  ![](C:IMG\ping-kali1-attacker.png)

  局域网intnet1内靶机可以访问攻击者主机

  ![](C:IMG\ping-debain2-attacker.png)

  ![](C:IMG\ping-xp2-attacker.png)

- 攻击者主机无法直接访问靶机

攻击者主机访问intnet0内的靶机

![](C:IMG\ping-attacker-0.png)

攻击者主机访问intnet1内的靶机

![](C:IMG\ping-attacker-1.png)

- 网关可以直接访问靶机和攻击者主机

网关访问攻击者主机

![](C:IMG\ping-gw-attacker.png)

网关访问intnet0内靶机

![](C:IMG\ping-gw-kali1.png)

![](C:IMG\ping-gw-xp1.png)

网关访问intnet1内靶机

![](C:IMG\ping-gw-xp2.png)

![](C:IMG\ping-gw-debain2.png)

- 靶机的所有上过流量必须经过网关

  在debain-gw上安装tmux

  ```
  apt update && apt install tmux
  apt install tcpdump
  tcpdump -i enp0s10 -n -w 202109.pcap 
  ```

将所抓包克隆到本地

![](C:IMG\gw-monitor0.png)

![](C:IMG\gw-monitor.png)

- 所有节点都可以访问互联网

  网关可以访问![](C:IMG\gw-internet.png)

attacker-kali![](C:IMG\attacker-kali-internet.png)

victim-xp-1![](C:IMG\xp1-internet.png)

victim-kali-1![](C:IMG\kali1-internet.png)

victim-xp-2![](C:IMG\xp2-internet.png)

victim-debain-2![](C:IMG\debain2-internet.png)

## 五、问题

- SSH服务无法连接：permission denied please try again

解决方法：输入：vi /etc/ssh/sshd_config

找到：

```
\# Authentication:
LoginGraceTime 2m
\#PermitRootLogin without-password
#StrictModes yes
```

改为：

```
\# Authentication:
LoginGraceTime 2m
\#PermitRootLogin without-password
PermitRootLogin yes
StrictModes yes
```

即可解决！

- 网关在ping xp1和xp2均不通

  解决方法：关闭xp机的防火墙

## 六、参考文献

[解决Ubuntu的root账号无法登录SSH问题-Permission denied, please try again_](https://blog.csdn.net/weiwei_pig/article/details/50954334)
