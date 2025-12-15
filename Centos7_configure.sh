#!/bin/bash
### This script handles the default configuration of RHEL 7 servers after initial install
### Script Created by Sydney
### Creation Date: 9 September 2014
### Added new IP Range for the IDC Servers.
### As requested By Nilkanth Sir added New Function for install Ldap Client on Centos 7 Servers ( 01-06-2023 Bhavesh P )
### As requested By Nilkanth Sir /keyur added New Function filebeat 8.8.2 setup added on Centos 7 Servers ( 25-01-2024 Bhavesh P )
### As requested By Nilkanth Sir /keyur added New Function for centos 7 Repo fix added on Centos 7 Servers ( 22-11-2024 Bhavesh P )
#########################################################################################

# Defining Script Variables
DEFAULT_INTERFACE=`ip route | grep default | awk '{ print $5 }'`
SYSTEM_IP=`/sbin/ip addr show $DEFAULT_INTERFACE | grep -w inet | awk '{ print $2 }' | cut -d '/' -f 1`
SUBNET_MASK=`/sbin/ip addr show $DEFAULT_INTERFACE | grep -w inet | awk '{ print $2 }' | cut -d '/' -f 2`
IP_OCTET2=`echo $SYSTEM_IP | cut -d "." -f 2`
IP_OCTET3=`echo $SYSTEM_IP | cut -d "." -f 3`
IP_OCTET4=`echo $SYSTEM_IP | cut -d "." -f 4`
IP_OCTET1=`echo $SYSTEM_IP | cut -d "." -f 1`
DOWNLOAD_DIR=/root/downloads_rhel7
WORKING_DIR=/tmp/rhel7
SRV_MANUFACTURER=`dmidecode -t system | grep "Manufacturer" | cut -d ":" -f 2 | awk '{ print $1 }'`
SRV_MODEL=`dmidecode -t system | grep "Product Name" | cut -d ":" -f 2`
USERS="web_backup keyur_016809 rajveer_10018295 bhavesh_10013754 pratik_013352"
#M_USER="sandeep sagar saiprasad umesh pavanr"
#S_USERS="web_backup nilkanth keyur tejas nishant"
DIR_NAME="/scripts /var/log/daily_log/processed /root/.ssh /home/web_backup/.ssh"
SERVICES="postfix firewalld iptables ip6tables"
SERVICES1="sshd autofs netfs"
################################
#Defining function for CITY_NAME
city_name () {
case $IP_OCTET3 in 
	0|80|81|67) CITY_NAME=mumbai;;
	8|82|83) CITY_NAME=delhi;;
	16|99) CITY_NAME=kolkata;;
	26|84|85|86|87) CITY_NAME=bangalore;;
	32|102|103) CITY_NAME=chennai;;
	40|93) CITY_NAME=pune;;
	50|97|98) CITY_NAME=hyderabad;;
	56|95) CITY_NAME=ahmedabad;;
	64) CITY_NAME=US;;
	176) CITY_NAME=mumbai;;
	1|6|7|11|12|13|14|15|16|17|18|22|23|24|25|29|30|31|32|33|35|39|41|42|43|44|45|46|47|48|51|56|57|59|61) CITY_NAME=IDC;;
esac
}
# Calling city_name function 
city_name
## End of function for city_name
################################

### Defining configuration Functions

function trap_exit {
clear
echo " "
echo " You hit Control-C! "
echo " Exiting "
sleep 5
exit 1
}
trap trap_exit SIGHUP SIGINT SIGTERM

proceed_further (){
if [ $? = 1 ]; then echo " The current configuration process failed with non-zero exit status.  Plz. manually check"; else echo -e " \e[32mDone :)\e[m "; fi
read -p "Proceed to next step (Y/N)" PF
if [ $PF = Y ] || [ $PF = y ]
then
echo "Proceeding to next step"
clear
else
echo " Quitting Script "
clear
exit 1
fi
}

##Function for Centos Channel Registration on Spacewalk
centos_reg () {
       
echo "Registering Spacewalk client using  yum "
       #rpm -Uvh http://yum.spacewalkproject.org/2.5-client/RHEL/7/x86_64/spacewalk-client-repo-2.5-3.el7.noarch.rpm
       rpm -Uvh https://copr-be.cloud.fedoraproject.org/archive/spacewalk/2.5-client/RHEL/7/x86_64/spacewalk-client-repo-2.5-3.el7.noarch.rpm 
       sed -i '/^gpgkey/d' /etc/yum.repos.d/spacewalk-client.repo
       sed -i '/^baseurl/d' /etc/yum.repos.d/spacewalk-client.repo       
       sed -i '3i baseurl=https://copr-be.cloud.fedoraproject.org/archive/spacewalk/2.5/RHEL/7/$basearch/' /etc/yum.repos.d/spacewalk-client.repo
       sed -i '4i gpgkey=https://copr-be.cloud.fedoraproject.org/archive/spacewalk/RPM-GPG-KEY-spacewalk-2015' /etc/yum.repos.d/spacewalk-client.repo
       echo "Adding epel repo on client"
       yum install -y epel-release
 
       echo " Installing osad & updating packages "
       yum -y install osad
       service osad start; chkconfig osad on; chkconfig ntpd on; chkconfig autofs on ;

       echo " Installing RHNCFG packages for Configuration Channel Management "
       yum -y install  rhn-client-tools rhn-check rhn-setup rhnsd m2crypto yum-rhn-plugin
       sed -i 's/enabled = 1/enabled = 0/' /etc/yum/pluginconf.d/rhnplugin.conf
       #rhn-actions-control --enable-all

echo " Registering with Spacewalk Server "
if [ `grep 172.29.0.249 /etc/hosts | wc -l` = 0 ]; then echo "172.29.0.249  jdspacewalk.jdsat.com  jdspacewalk" >> /etc/hosts; fi
wget -O /usr/share/rhn/RHN-ORG-TRUSTED-SSL-CERT http://jdspacewalk.jdsat.com/pub/RHN-ORG-TRUSTED-SSL-CERT
sed -i 's/serverURL=.*/serverURL=https:\/\/jdspacewalk.jdsat.com\/XMLRPC/g' /etc/sysconfig/rhn/up2date
sed -i 's/sslCACert=.*/sslCACert=\/usr\/share\/rhn\/RHN-ORG-TRUSTED-SSL-CERT/g' /etc/sysconfig/rhn/up2date
echo "Spacewalk Registration Option. Select from options below ( 1 ) "
echo "1 - Centos 7"
read -p "Your Choice" OS
case $OS in
        1) echo " Registering with Centos 7 Key ";
           rhnreg_ks --force --activationkey=1-01e2cb6375e00bd3fccaed3f2e6b5f88;;
        
        2) echo " Registering with Centos 7.02 Key ";
           rhnreg_ks --force --activationkey=1-67c114b47195912eed73bc110a0c3010;;
 
        *) echo "Invalid choice"; exit 1;;
esac
}

mandatory_config () {

read -p "Plz. type your name: `echo $'\n> '`" NAME

### Preliminary & dependent tasks for RHEL7 Software Configuration Tuning
echo " Downloading custom files from 172.29.0.123. Plz. wait... "
cd /root && curl -O http://172.29.0.123/download/downloads_rhel7.tar.gz
if [ -e $DOWNLOAD_DIR ]
then 
echo " Directory /root/downloads_rhel7 already exists "
echo " Not extracting compressed file "
else
tar zxvf downloads_rhel7.tar.gz
fi

mkdir -p $WORKING_DIR
sleep 5
clear

### Basic Server Configuration Tuning
echo " Starting with Basic & Mandatory Software Configuration Changes for RHEL 7"

### Configure Hostname
echo " Configuring Hostname Settings "

case $IP_OCTET3 in 
          0|80|81|67|86|8|82|83|16|99|26|84|85|87|32|102|103|40|93|50|97|98|56|95|64|176|1|6|7|11|12|13|14|15|16|17|18|22|23|24|25|29|30|31|32|33|35|39|41|42|43|44|45|46|47|48|51|56) SYS_NAME=$IP_OCTET3-$IP_OCTET4-$CITY_NAME.justdial.com
        if [ "$IP_OCTET1" == "192" -a "$IP_OCTET2" == "168" ]
        then
        CITY_NAME="IDC"
        SYS_NAME="$IP_OCTET3-$IP_OCTET4-$CITY_NAME.justdial.com"
fi
;;  
        67) SYS_NAME=$IP_OCTET3-$IP_OCTET4-${CITY_NAME}-dvp.justdial.com;;
	* ) SYS_NAME=$IP_OCTET3-$IP_OCTET4-$CITY_NAME.justdial.com;;
esac

if [ $IP_OCTET3 = 176 ];then
	echo "Plz. configure Hostname settings manually"
fi
        
#if [ -z "$CITY_NAME" -o $IP_OCTET3 -o $IP_OCTET4 ]
if [ -z "$CITY_NAME" ] || [ -z "$IP_OCTET3" ] || [ -z "$IP_OCTET4" ]
then
	echo "Plz. configure Hostname settings manually"
else
	sed -i "s/HOSTNAME.*/HOSTNAME=$SYS_NAME/g" /etc/sysconfig/network
	sed -i "s/127.0.0.1.*/127.0.0.1 \tlocalhost \tlocalhost.localdomain \t$SYS_NAME \t$IP_OCTET3-$IP_OCTET4-$CITY_NAME/g" /etc/hosts
	echo $SYS_NAME > /proc/sys/kernel/hostname
	sed -i "s/ONBOOT.*/ONBOOT=yes/g" /etc/sysconfig/network-scripts/ifcfg-${DEFAULT_INTERFACE}
        `hostnamectl set-hostname ${SYS_NAME} --static`
       `hostnamectl set-hostname Your-New-Host-Name-Here --transient`
fi

proceed_further

echo "Setting NetworkDelay"
grep -q ^NETWORKDELAY /etc/sysconfig/network
if [ $? -ne 0 ];then
echo "NETWORKDELAY=60" >> /etc/sysconfig/network
fi
proceed_further

#### Updating resolver 
echo "Emptying Contents of resolv.conf"
> /etc/resolv.conf
proceed_further

echo "nameserver 23.59.248.145" >> /etc/resolv.conf
echo "nameserver 23.59.249.145" >> /etc/resolv.conf
echo "nameserver 8.8.8.8"  >> /etc/resolv.conf
echo "nameserver 115.112.18.130"  >> /etc/resolv.conf
echo "nameserver 115.112.18.22"  >> /etc/resolv.conf
proceed_further

### RedHat Satellite Installation & Registration

read -p "Plz. specify where the server need to be registered - SPACEWALK / SATELLITE / CENTOS (Select Centos) `echo $'\n> '`" RHN
case $RHN in
	SPACEWALK) echo "Registering on Spacewalk"; spacewalk_reg;;
	SATELLITE) echo "Registering on Satellite"; satellite_reg;;
        CENTOS) echo "Registering on CENTOS";centos_reg;;
esac

proceed_further

sed -i 's/enabled = 1/enabled = 0/' /etc/yum/pluginconf.d/rhnplugin.conf

### Download Additional Packages from Satellite through YUM
echo " Install miscellaneous packages - curl, telnet etc... "
yum -y install gcc telnet curl lynx unzip telnet automake autoconf lsscsi net-snmp dstat iptraf sysstat screen wget vim-enhanced iptables-services iperf tcpdump traceroute bc mlocate rsync ntp net-tools psmisc mysql cyrus-sasl-plain bind-utils strace subversion git perl-Digest-HMAC jq nc
proceed_further

### Enforcing Linux Password Policy
echo " Configuring Password policy "
cp /etc/pam.d/system-auth $WORKING_DIR/
cp /etc/login.defs  $WORKING_DIR/
#sed -i 's/^\(.*\) pam_cracklib.so.*$/\1 pam_passwdqc.so min=disabled,disabled,16,12,8/' /etc/pam.d/system-auth
echo "password    required    pam_pwquality.so retry=3" >> /etc/pam.d/passwd
authconfig --enablereqother --enablereqdigit --enablerequpper --enablereqlower --passmaxclassrepeat=4 --passminlen=16 --passmaxrepeat=3 --update
#echo "minlen = 8" >> /etc/security/pwquality.conf
#echo "minclass = 4" >> /etc/security/pwquality.conf
#echo "maxsequence = 3" >> /etc/security/pwquality.conf
#echo "maxrepeat = 3" >> /etc/security/pwquality.conf
#echo "dcredit = 1" >> /etc/security/pwquality.conf
#echo "ucredit = 1" >> /etc/security/pwquality.conf
#echo "lcredit = 1" >> /etc/security/pwquality.conf
#echo "0credit = 1" >> /etc/security/pwquality.conf
echo "PASS_MIN_LEN" | sed -i 's/5/16/g' /etc/login.defs
echo "PASS_MAX_DAYS" | sed -i 's/99999/120/g' /etc/login.defs
perl -pi -w -e 's/MD16_CRYPT_ENAB/#MD16_CRYPT_ENAB/g;' /etc/login.defs
sed -i 's/MD16_CRYPT_ENAB.*/#MD16_CRYPT_ENAB no/g' /etc/login.defs

### Linux System User Creation
echo " Creating Shell Accounts for Linux team members & sudoers additions "
cp /etc/sudoers /etc/sudoers_`date +%d%m%Y`

read -p "Is this System being configured for Shreos? ( Y / N ) `echo $'\n> '`" INSTALL_OPTION
if [ $INSTALL_OPTION = Y ] || [ $INSTALL_OPTION = y ]
then
	echo "Creating limited number of users as predefined"
	USERS="web_backup nilkanth keyur tejas"
fi

for musername in $M_USER
do
######### monitoring team ############
          if [ -z `grep $musername /etc/passwd` ]; then
                /usr/sbin/useradd $musername
             echo ju5tD1@lcr0mA | /usr/bin/passwd --stdin $musername
             echo "$musername  ALL = NOPASSWD: ALL, !/bin/su, !/usr/bin/passwd, !/bin/bash, !/usr/sbin/visudo" >> /etc/sudoers	
	else
        echo "User already exists"
        fi
done

for username in $USERS
do
#### Checking if user exists ####
	  if [ -z `grep $username /etc/passwd` ]; then
        	/usr/sbin/useradd $username
	     if [ $username = mumbainoc ]; then
             echo p@lMspr1ng | /usr/bin/passwd --stdin $username
	     elif [ $username = soc ];then
	     echo "S0cJd@1234" | /usr/bin/passwd --stdin $username
	     else
             echo ju5tD1@lcr0mA | /usr/bin/passwd --stdin $username
             fi
        else
        echo "User already exists"
        fi

#### Checking if sudo entry exists ###

	if [ -z `grep $username /etc/sudoers | awk '{ print $1 }'` ]
	then
		if  [ $username = web_backup ]
		then
	       #echo "web_backup ALL = NOPASSWD: /bin/chown, /usr/bin/rsync, /usr/bin/ssh, /usr/bin/scp" | tee -a /etc/sudoers
		echo "web_backup ALL = NOPASSWD: ALL, !/bin/su" | tee -a /etc/sudoers
		elif [ $username = mumbainoc ]
		then
		echo "mumbainoc ALL = NOPASSWD: ALL, !/bin/su, !/usr/bin/passwd, !/bin/bash, !/usr/sbin/visudo" | tee -a /etc/sudoers
                elif [ $username = soc ]
		then
		echo "soc ALL = NOPASSWD: ALL, !/bin/su, !/usr/bin/passwd, !/bin/bash,  !/usr/sbin/visudo, !/bin/mount" | tee -a /etc/sudoers
        	else
	        echo "${username} ALL = NOPASSWD: ALL, !/bin/su" | tee -a /etc/sudoers
		fi
	else
	echo " sudo entry already exists "
	fi
done

## Adding sudo entry for web_backup user
#echo "web_backup ALL = NOPASSWD: /bin/chown, /usr/bin/rsync, /usr/bin/ssh, /usr/bin/scp" | tee -a /etc/sudoers

proceed_further

## Disabling require tty in sudo
echo " Disabling tty for sudo "
sed -i 's/Defaults    requiretty/#Defaults    requiretty/g' /etc/sudoers

proceed_further

### Creating of requisite directories
echo " Creating basic / necessary directory structure "
for dir in $DIR_NAME; do if [ ! -d $dir ]; then mkdir -p $dir; fi; done
mkdir -p /SERVER_BACKUP/{web_backup,SQL_BACKUP}
chmod 775 -R /SERVER_BACKUP/
chown web_backup:web_backup -R /SERVER_BACKUP/
echo "$CITY_NAME" > /home/web_backup/city_name
echo "$SYSTEM_IP" > /home/web_backup/ip_addr.txt
echo "$IP_OCTET3" > /home/web_backup/network_addr.txt
cp $DOWNLOAD_DIR/find_ct_digit.sh $DOWNLOAD_DIR/server_conf_bkp.sh $DOWNLOAD_DIR/linux_requisite_check.sh $DOWNLOAD_DIR/sysmon.sh  $DOWNLOAD_DIR/fetch_server_utilization.sh  $DOWNLOAD_DIR/Kernel_Error_Messages.sh $DOWNLOAD_DIR/standard_sms_sending_script.sh $DOWNLOAD_DIR/ansible_connectivity_state.sh $DOWNLOAD_DIR/check_logrotate.sh $DOWNLOAD_DIR/find-ip-addr.sh $DOWNLOAD_DIR/active_ip.sh  $DOWNLOAD_DIR/pan_genio_ip.ini $DOWNLOAD_DIR/io_utilization_report.sh /scripts/

proceed_further

### Configuring Password-less login
###Adding config file in .ssh (#5919 - assigned by pushkar )
echo " Passwordless SSH login for web_backup & root "
cp -ar $DOWNLOAD_DIR/ssh_keys/* /home/web_backup/.ssh
cp -ar $DOWNLOAD_DIR/ssh_keys/* /root/.ssh
cp $DOWNLOAD_DIR/config /root/.ssh/
cp $DOWNLOAD_DIR/config /home/web_backup/.ssh/
chmod 700 /home/web_backup/.ssh /root/.ssh
chmod 600 /home/web_backup/.ssh/* /root/.ssh/*
chown web_backup:web_backup -R /home/web_backup/.ssh

proceed_further

## Disabling password expiry for web_backup
chage -I -1 -m 0 -M 99999 -E -1 web_backup

proceed_further

### SNMP conf file
echo " Copying snmpd.conf file"
cp -v $DOWNLOAD_DIR/snmpd.conf /etc/snmp/
systemctl enable snmpd && systemctl start snmpd

echo "Disabling SNMPv2 and Enabling SNMPv3"
curl -s http://172.29.0.123/download/saiteja/enable_snmpv3.sh | bash


proceed_further

### Disable Unnecessary Services
echo " Disabling few services from starting on system boot "
if [ $SRV_MANUFACTURER == IBM ]
then
for service_list in $SERVICES; do systemctl disable $service_list; systemctl stop $service_list; done
for service_list in $SERVICES1; do systemctl enable $service_list; systemctl start $service_list; done
else
for service_list in $SERVICES; do systemctl disable $service_list; systemctl stop $service_list; done
for service_list in $SERVICES1; do systemctl enable $service_list; systemctl start $service_list; done
fi

proceed_further

### Run Level Changes
echo " Setting the default runlevel - 3 "
#if [ ! -z `grep ^id /etc/inittab | grep 3` ]; then echo " Already at run level 3"; else sed -i 's/^id/id:3:initdefault/g' /etc/inittab; fi
`systemctl set-default multi-user.target`
proceed_further

### Disable SELinux
echo " Disabling SELinux "
cp /etc/selinux/config $WORKING_DIR && sed -i 's/^SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config
setenforce 0

### Disable Ctrl-Alt-Del keystroke
echo " Disabling Ctrl-Alt-Del "

ln -sf /dev/null /etc/systemd/system/ctrl-alt-del.target

proceed_further

### SSH Hardening
echo " Changing SSH parameters "
sed -i '/^Host *\*/ s/.*/&\n\tStrictHostKeyChecking no\n\tUserKnownHostsFile \/dev\/null/g' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin\ yes/PermitRootLogin\ no/g' /etc/ssh/sshd_config
sed -i 's/#Banner\ none/Banner\ \/etc\/issue/g' /etc/ssh/sshd_config
echo "## Added on recommendation of SOC Team # 09/09/2015 - Tejas Solanki" >> /etc/ssh/sshd_config
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config
echo "MACs hmac-sha1,hmac-ripemd160" >> /etc/ssh/sshd_config
#echo "KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
proceed_further

### VI Alias
echo " Configuring vi alias "
echo "alias vi=vim" >> /root/.bash_profile

### History Timestamp
echo " Enabling Timestamp for History Command "
echo "HISTTIMEFORMAT='[%F] [%T] '" >> /etc/profile
echo "export LC_CTYPE=en_US.UTF-8" >> /etc/profile
echo "export LC_ALL=en_US.UTF-8" >> /etc/profile

### Banner pages for Login
echo " Login Banner Pages "
mv /etc/issue $WORKING_DIR; cp $DOWNLOAD_DIR/issue /etc/issue
mv /etc/issue.net $WORKING_DIR; cp $DOWNLOAD_DIR/issue.net /etc/issue.net

### Adding tcp_tw_reuse to sysctl.conf ###
echo "Adding net.ipv4.tcp_tw_reuse, tcp_fin_timeout, ip_local_port_range, zone reclaim"
echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_fin_timeout = 10" >> /etc/sysctl.conf
echo "net.ipv4.ip_local_port_range = 1025    65535"  >> /etc/sysctl.conf
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
#grep -q ^vm.zone_reclaim_mode /etc/sysctl.conf
#if [ $? -ne 0 ];then
#echo -e "## TRACK 25076##\nvm.zone_reclaim_mode = 1" >> /etc/sysctl.conf
#fi
echo "vm.max_map_count = 256000" >> /etc/sysctl.conf
echo "net.core.netdev_max_backlog = 8192" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_tw_buckets = 2000000" >> /etc/sysctl.conf
echo "net.core.netdev_max_backlog = 8192" >> /etc/sysctl.conf
echo "net.core.somaxconn = 4096" >> /etc/sysctl.conf
echo "net.nf_conntrack_max = 5000000" >> /etc/sysctl.conf
echo "net.ipv4.tcp_no_metrics_save = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 8192" >> /etc/sysctl.conf
echo "net.ipv4.ip_local_reserved_ports=8000,9000,1080,5666,28001,28002,9200,3320,3306,8649,2000,8888,9210,3000,9090,8100,8181,8080,9001,8001,11211,1311,8651,6379,5601,7474,27017,15672,25672,5672,4369,8650,5050,5000,9300,4105,4104,8881,8882,8883,1025,3260" >> /etc/sysctl.conf
echo "vm.swappiness = 10" >> /etc/sysctl.conf
#### Set TimeZone ####
timedatectl set-timezone Asia/Kolkata

### Logrotate Global Settings 
echo " Logrotate Global Settings "
sed -i 's/^weekly/daily/g' /etc/logrotate.conf
sed -i 's/#\ rotate\ log.*/#\ rotate\ log\ files\ daily/g' /etc/logrotate.conf
sed -i 's/^rotate.*/rotate\ 30/g' /etc/logrotate.conf
sed -i 's/^#\ keep.*/#\ keep\ 30\ days\ worth\ of\ backlogs/g' /etc/logrotate.conf
sed -i 's/#compress/compress/g' /etc/logrotate.conf

proceed_further

### Default Crons to be scheduled
echo " Configuring default cron jobs "
echo "MAILTO=linux@justdial.com" > /var/spool/cron/root

#if [ "$IP_OCTET1" == "192" -a "$IP_OCTET3" == "1|6|7|11|12|13|14|15|16|17|18|22|23|24|25|28|29|30|32|33|35|39|43|44|45|46|47|48|51|56" ]
if [ "$IP_OCTET1" == "192" -a "$IP_OCTET2" == "168" ]
then
echo "0 * * * * /usr/sbin/ntpdate -u 192.168.1.101 > /dev/null 2>&1; /sbin/hwclock  --systohc > /dev/null 2>&1" >> /var/spool/cron/root

elif  [ $IP_OCTET3 = 0 ] || [ $IP_OCTET3 = 81 ] || [ $IP_OCTET3 = 80 ] || [ $IP_OCTET3 = 64 ]
then
echo "0 * * * * /usr/sbin/ntpdate -u 172.29.0.123 > /dev/null 2>&1; /sbin/hwclock  --systohc > /dev/null 2>&1" >> /var/spool/cron/root

elif  [ $IP_OCTET3 = 8 ] || [ $IP_OCTET3 = 82 ] || [ $IP_OCTET3 = 83 ]
then
echo "0 * * * * /usr/sbin/ntpdate -u 172.29.8.123 > /dev/null 2>&1; /sbin/hwclock  --systohc > /dev/null 2>&1" >> /var/spool/cron/root

elif  [ $IP_OCTET3 = 26 ] || [ $IP_OCTET3 = 84 ] || [ $IP_OCTET3 = 85 ]
then
echo "0 * * * * /usr/sbin/ntpdate -u 172.29.26.123 > /dev/null 2>&1; /sbin/hwclock  --systohc > /dev/null 2>&1" >> /var/spool/cron/root

elif  [ $IP_OCTET3 = 32 ] || [ $IP_OCTET3 = 102 ] || [ $IP_OCTET3 = 103 ]
then
echo "0 * * * * /usr/sbin/ntpdate -u 172.29.32.123 > /dev/null 2>&1; /sbin/hwclock  --systohc > /dev/null 2>&1" >> /var/spool/cron/root

elif [ $IP_OCTET3 = 40 ] || [ $IP_OCTET3 = 93 ]
then
echo "0 * * * * /usr/sbin/ntpdate -u 172.29.40.123 > /dev/null 2>&1; /sbin/hwclock  --systohc > /dev/null 2>&1" >> /var/spool/cron/root

elif  [ $IP_OCTET3 = 50 ] || [ $IP_OCTET3 = 97 ] || [ $IP_OCTET3 = 98 ]
then
echo "0 * * * * /usr/sbin/ntpdate -u 172.29.50.123 > /dev/null 2>&1; /sbin/hwclock  --systohc > /dev/null 2>&1" >> /var/spool/cron/root

elif [ $IP_OCTET3 = 56 ] || [ $IP_OCTET3 = 95 ] 
then
echo "0 * * * * /usr/sbin/ntpdate -u 172.29.56.123 > /dev/null 2>&1; /sbin/hwclock  --systohc > /dev/null 2>&1" >> /var/spool/cron/root

elif [ $IP_OCTET3 = 16 ] || [ $IP_OCTET3 = 99 ]
then
echo "0 * * * * /usr/sbin/ntpdate -u 172.29.16.123 > /dev/null 2>&1; /sbin/hwclock  --systohc > /dev/null 2>&1" >> /var/spool/cron/root

elif [ $IP_OCTET3 = 67 ]
then
echo "0 * * * * /usr/sbin/ntpdate -u 172.29.0.123 > /dev/null 2>&1; /sbin/hwclock  --systohc > /dev/null 2>&1" >> /var/spool/cron/root
else
echo "0 * * * * /usr/sbin/ntpdate -u 172.29.$IP_OCTET3.123 > /dev/null 2>&1; /sbin/hwclock  --systohc > /dev/null 2>&1" >> /var/spool/cron/root
fi
echo "" >> /var/spool/cron/root
echo "#Server Configuration Backup" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "00 07 * * * /scripts/server_conf_bkp.sh > /var/log/daily_log/server_conf_bkp.log 2>&1" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "# Linux pre-req check script" >> /var/spool/cron/root
echo "#*/30 * * * * /scripts/linux_requisite_check.sh > /var/log/linux_pre-req.log 2>&1" >> /var/spool/cron/root
echo "*/30 * * * *  curl -s  http://172.29.0.123/download/INVENTORY/linux_requisite_check.sh  | sudo bash -s  > /var/log/daily_log/linux_requisite_check.log 2>&1" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "# Sysmon script" >> /var/spool/cron/root
echo "* * * * * /scripts/sysmon.sh > /dev/null 2>&1" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "################## Server Utilization Fetching Cron ########################" >> /var/spool/cron/root
echo "00 01 * * *  curl -s  http://172.29.0.123/download/scripts/fetch_server_utilization.sh  | sudo bash -s  > /var/log/daily_log/fetch_server_utilization.log 2>&1" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root 
echo "#### sachin Checking Diskspace on PHP ####" >> /var/spool/cron/root
echo "00 * * * * curl -s http://172.29.0.123/download/diskspace.sh | bash -s > /var/log/daily_log/diskspace.log 2>&1" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "###########################################" >> /var/spool/cron/root
echo "##### Auto Inventory cron                 #" >> /var/spool/cron/root
echo "###########################################" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "30 12 * * * curl -s http://172.29.0.123/download/INVENTORY/Auto_inventory.sh | sudo bash -s > /var/log/daily_log/Auto_inventory.log 2>&1" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "###########################################" >> /var/spool/cron/root
echo "##### Kernel Messages Cron                #" >> /var/spool/cron/root
echo "###########################################" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "00 */1 * * * sh /scripts/Kernel_Error_Messages.sh> /var/log/daily_log/Kernel_Error_Messages.log 2>&1" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "################## Ansible connectivity test_##################" >> /var/spool/cron/root
echo "00 01-23 * * *  sh /scripts/ansible_connectivity_state.sh > /var/log/daily_log/ansible_connectivity_state.log 2>&1" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "##### io_utilization_report_#######" >> /var/spool/cron/root
echo "*/10 * * * * /bin/bash /scripts/io_utilization_report.sh > /var/log/daily_log/io_utilization_report.log 2>&1" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "00 06 * * * sh /scripts/check_logrotate.sh > /var/log/daily_log/logrotate.log 2>&1" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "00 10 * * * curl -s http://172.29.0.123/download/INVENTORY/new_auto_inventory.sh | sudo bash -s > /var/log/daily_log/new_auto_inventory.log 2>&1" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "#Ansible: #-- bash login details --#" >> /var/spool/cron/root
echo "45 11 * * * curl -s http://172.29.0.123/download/scripts/login-detail.sh | sudo bash -s > /var/log/daily_log/login-detail.log 2>&1" >> /var/spool/cron/root
echo "" >> /var/spool/cron/root
echo "##############################" >> /var/spool/cron/root
echo "#-- NF Conntrack ERROR REPORT#" >> /var/spool/cron/root
echo "##############################" >> /var/spool/cron/root
echo "*/5 * * * * curl -s http://172.29.0.123/download/nf_conntrack_error_reporting.sh | sudo bash -s >> /var/log/daily_log/nf_conntrack_error_reporting.log 2>&1" >> /var/spool/cron/root

systemctl enable crond

proceed_further

### Avamar Installation
echo " Installing Avamar Package for Centos 7. "
rpm -qa |grep -i "Avamar"
if [ $? -eq 0 ]; then echo "Avamar already installed"; else echo "Installing Avamar...." ; yum -y --nogpgcheck localinstall $DOWNLOAD_DIR/AvamarClient-linux-sles11-x86_64-19.4.100-116.rpm; if [ $? -ne 0 ]; then echo "Installation error...Please check" && exit 2; fi; fi

proceed_further

### RKHunter Installation
echo " RKHunter Installation "
yum -y --nogpgcheck install rkhunter

proceed_further

### Sendmail Installation
echo " Starting sendmail installation "
yum -y install sendmail-cf sendmail
cp /etc/mail/sendmail.cf $WORKING_DIR; cp /etc/mail/sendmail.mc $WORKING_DIR
#sed -i "s/dnl\ FEATURE(masquerade_envelope)dnl/FEATURE(masquerade_envelope)dnl\nFEATURE(\`genericstable')dnl\nGENERICS_DOMAIN(\`"$HOSTNAME"')dnl/g" /etc/mail/sendmail.mc
#sed -i "/.*root.*/d" /etc/mail/sendmail.mc
#sed -i "s/.*MASQUERADE_AS.*dnl$/MASQUERADE_AS(\`justdial.com')dnl/g" /etc/mail/sendmail.mc
#sed -i "s/.*SMART_HOST.*/define(\`SMART_HOST'\, \`smtp10.netcore.co.in')dnl/g" /etc/mail/sendmail.mc
#m4 /etc/mail/sendmail.mc > /etc/mail/sendmail.cf
#echo "root	root@justdial.com" > /etc/mail/genericstable
#makemap hash /etc/mail/genericstable < /etc/mail/genericstable 
#systemctl stop postfix && systemctl disable postfix
#systemctl start sendmail && systemctl enable sendmail

#################### Step Added for New Changes 25072018 ##################################
#cp -f $DOWNLOAD_DIR/sendmail.mc  /etc/mail/sendmail.mc
#mkdir -p /etc/mail/auth && chown -R root.root /etc/mail/auth && chmod 0700 /etc/mail/auth && sudo chown root /etc/mail
##touch /etc/mail/auth/authinfo
#cp -f $DOWNLOAD_DIR/authinfo /etc/mail/auth/ && chmod 0700 /etc/mail/auth/authinfo
#cd /etc/mail/auth ; makemap hash authinfo < authinfo
#cd /etc/mail ; makemap hash access < access
#cd /etc/mail ; m4 sendmail.mc > sendmail.cf
#echo "root	root@justdial.com" > /etc/mail/genericstable
#makemap hash /etc/mail/genericstable < /etc/mail/genericstable 
#echo "mech_list: LOGIN PLAIN" >> /etc/sasl2/Sendmail.conf
#systemctl stop postfix && systemctl disable postfix
#systemctl start sendmail && systemctl enable sendmail
#systemctl start saslauthd && systemctl enable saslauthd

############### New Sendmail configuration changes 25-07-2022 #############################

cp -f $DOWNLOAD_DIR/sendmail.mc  /etc/mail/sendmail.mc
mkdir -p /etc/mail/auth && chown -R root.root /etc/mail/auth && chmod 0700 /etc/mail/auth && sudo chown root /etc/mail
cp -f $DOWNLOAD_DIR/mailertable  /etc/mail/mailertable
cd /etc/mail/ ; makemap hash /etc/mail/mailertable < /etc/mail/mailertable

cp -f $DOWNLOAD_DIR/authinfo /etc/mail/auth/ && chmod 0700 /etc/mail/auth/authinfo
cd /etc/mail/auth ; makemap hash authinfo < authinfo
cd /etc/mail ; makemap hash access < access
cd /etc/mail ; m4 sendmail.mc > sendmail.cf

echo "root      root@justdial.com" > /etc/mail/genericstable
makemap hash /etc/mail/genericstable < /etc/mail/genericstable
echo "mech_list: LOGIN PLAIN" >> /etc/sasl2/Sendmail.conf

systemctl stop postfix && systemctl disable postfix
systemctl start sendmail && systemctl enable sendmail
systemctl start saslauthd && systemctl enable saslauthd

systemctl restart sendmail && systemctl restart saslauthd


proceed_further

####Anacrontab changes
cp /etc/anacrontab /etc/anacrontab_default

sed -i 's/^RANDOM_DELAY=45/RANDOM_DELAY=0/g' /etc/anacrontab

sed -i 's/^START_HOURS_RANGE=3-22/START_HOURS_RANGE=0-23/g' /etc/anacrontab

proceed_further
### NRPE Installation
echo " NRPE installation "
yum -y --nogpgcheck install nagios-nrpe xinetd

cp $DOWNLOAD_DIR/nrpe /etc/xinetd.d/

sed -i 's/disable.*/disable\         =\ no/g' /etc/xinetd.d/nrpe

sed -i 's/server_address/#server_address/g' /etc/nagios/nrpe.cfg

if [ "$IP_OCTET1" == "192" -a "$IP_OCTET3" == "16" ]
then
sed -i 's/allowed_hosts=127.0.0.1/allowed_hosts=127.0.0.1,192.168.11.123,192.168.12.78/g' /etc/xinetd.d/nrpe
else
echo "No changes required"
fi

if [ $IP_OCTET3 = 1 ] || [ $IP_OCTET3 = 6 ] || [ $IP_OCTET3 = 7 ] || [ $IP_OCTET3 = 11 ] || [ $IP_OCTET3 = 12 ] || [ $IP_OCTET3 = 13 ] || [ $IP_OCTET3 = 24 ]
then
sed -i 's/allowed_hosts=127.0.0.1/allowed_hosts=127.0.0.1,192.168.11.123/g' /etc/xinetd.d/nrpe
elif [ $IP_OCTET3 = 0 ] || [ $IP_OCTET3 = 80 ] || [ $IP_OCTET3 = 81 ] || [ $IP_OCTET3 = 64 ]
then
sed -i 's/allowed_hosts=127.0.0.1/allowed_hosts=127.0.0.1,172.29.0.123/g' /etc/xinetd.d/nrpe
elif [ $IP_OCTET3 = 8 ] || [ $IP_OCTET3 = 82 ] || [ $IP_OCTET3 = 83 ]
then
sed -i 's/allowed_hosts=127.0.0.1/allowed_hosts=127.0.0.1,172.29.8.123/g' /etc/xinetd.d/nrpe
elif [ $IP_OCTET3 = 26 ] || [ $IP_OCTET3 = 84 ] || [ $IP_OCTET3 = 85 ]
then
sed -i 's/allowed_hosts=127.0.0.1/allowed_hosts=127.0.0.1,172.29.26.123/g' /etc/xinetd.d/nrpe
elif [ $IP_OCTET3 = 40 ] || [ $IP_OCTET3 = 93 ]
then
sed -i 's/allowed_hosts=127.0.0.1/allowed_hosts=127.0.0.1,172.29.40.123/g' /etc/xinetd.d/nrpe
elif [ $IP_OCTET3 = 56 ] || [ $IP_OCTET3 = 95 ]
then
sed -i 's/allowed_hosts=127.0.0.1/allowed_hosts=127.0.0.1,172.29.56.123/g' /etc/xinetd.d/nrpe
elif [ $IP_OCTET3 = 16 ] || [ $IP_OCTET3 = 99 ]
then
sed -i 's/allowed_hosts=127.0.0.1/allowed_hosts=127.0.0.1,172.29.16.123/g' /etc/xinetd.d/nrpe
else
sed -i "s/allowed_hosts=127.0.0.1/allowed_hosts=127.0.0.1,172.29.$IP_OCTET3.123/g" /etc/xinetd.d/nrpe
fi
systemctl restart nrpe
echo "nagios ALL = NOPASSWD: /usr/lib64/nagios/plugins/" | tee -a /etc/sudoers

proceed_further

## OCS Inventory Installation
#echo "OCSInventory Installation" 
#yum -y install ocsinventory-agent perl-LWP-Protocol-https
#sed -i 's/OCSMODE\[0\]=none/OCSMODE[0]=cron/g' /etc/sysconfig/ocsinventory-agent
#sed -i 's/\#\ OCSSERVER\[0\]=your.ocsserver.name/OCSSERVER[0]=http:\/\/172.29.0.49\/ocsinventory\//g' /etc/sysconfig/ocsinventory-agent
#sed -i 's/local/#local/g;s/#server.*/server\ =\ http:\/\/172.29.0.49\/ocsinventory\//g' /etc/ocsinventory/ocsinventory-agent.cfg 
#ocsinventory-agent -f --info --server=http://172.29.0.49/ocsinventory --tag=${CITY_NAME}
#
#proceed_further

## Default process values counters

echo "Increasing the default process values"
sed -i 's/1024/8196/g' /etc/security/limits.d/20-nproc.conf

echo "" >> /etc/security/limits.d/20-nproc.conf
echo "* soft    nofile   8196" >> /etc/security/limits.d/20-nproc.conf
echo "* hard    nofile   8196" >> /etc/security/limits.d/20-nproc.conf
echo "* soft    nproc    8196" >> /etc/security/limits.d/20-nproc.conf
echo "* hard    nproc    8196" >> /etc/security/limits.d/20-nproc.conf
echo "root soft    nproc    unlimited" >> /etc/security/limits.d/20-nproc.conf
echo "root hard    nproc    unlimited" >> /etc/security/limits.d/20-nproc.conf


echo "Increasing the no of open files"
echo -e "*      soft    nofile  8196\n* hard    nofile  8196" >> /etc/security/limits.conf
echo -e "*      soft    nproc   8196\n* hard    nproc   8196" >> /etc/security/limits.conf
echo -e "root   soft    nproc   unlimited\nroot    hard    nproc        unlimited" >> /etc/security/limits.conf
proceed_further

echo "Starting and Enable NTPD Services"
systemctl start ntpd
systemctl enable ntpd  
proceed_further

echo "Installing Ldap Clinet."
#curl http://172.29.0.123/download/openldap_setup/ldapclient_setup_sssd_centos7.sh | sudo bash -x
wget -q -O /tmp/ldapclient_setup_sssd_centos7_new.sh http://172.29.0.123/download/openldap_setup/ldapclient_setup_sssd_centos7_new.sh && sudo sh /tmp/ldapclient_setup_sssd_centos7_new.sh
proceed_further


echo "Check the Installed Kernel Version."
wget -q -O /tmp/check_kernel_version.sh http://172.29.0.123/download/check_kernel_version.sh && sudo bash /tmp/check_kernel_version.sh
proceed_further

echo "Changing root Password.."
wget -O /tmp/root_password_reset.sh "http://172.29.0.123/download/INVENTORY/root_password_reset.sh" && sh /tmp/root_password_reset.sh
proceed_further


echo "Setting Up filebeat8.8 for the server logs "
curl -s http://172.29.0.123/download/INVENTORY/filebeat_8.8.2_for_syslog_deploy.sh | sudo bash -s
proceed_further

#### Again Updating resolver 
echo "Emptying Contents of resolv.conf"
> /etc/resolv.conf
echo "nameserver 23.59.248.145" >> /etc/resolv.conf
echo "nameserver 23.59.249.145" >> /etc/resolv.conf
echo "nameserver 8.8.8.8"  >> /etc/resolv.conf
echo "nameserver 115.112.18.130"  >> /etc/resolv.conf
echo "nameserver 115.112.18.22"  >> /etc/resolv.conf


#### Configure Nginx Logs and container logs Dir Streture For .XZ logs storage. 
echo "Creating Nginx Logs and container logs Dir Streture For .XZ logs storage."

mkdir -p /var/log/nginx/BACKUP/Day{01..31}/{NGinx,Container}
chown -R web_backup.root /var/log/nginx/BACKUP/
chmod 755 -R /var/log/nginx/BACKUP/

mkdir -p /var/log/nginx/BACKUP_PAIDLOG/Day{01..31}/{NGinx,Container}
chown -R web_backup.root /var/log/nginx/BACKUP_PAIDLOG/
chmod 755 -R /var/log/nginx/BACKUP_PAIDLOG/

echo "Creating dir for cron logs"
mkdir -p /var/log/daily_log/



#echo "Execute the command after server restart witjoit fail!!!!!! ---->> wget -O /tmp/root_password_reset.sh "http://172.29.0.123/download/INVENTORY/root_password_reset.sh" && sh /tmp/root_password_reset.sh"; sleep 15; clear


SERI=`dmidecode -t 1 | grep -i "Serial" | awk '{print $3}'`
OSS=`cat /etc/redhat-release`
OSS_VER=`uname -a`
DMI=`dmidecode -t 1`
DDATE=`date`
LAST=`last | head -n 10`
DISKK=`df -hT`

echo "Server Hardening Done on $SYSTEM_IP Serial = ${SERI} " | mail -s "New Installation on $SYSTEM_IP $HOSTNAME  $SERI done by $NAME" sachinthore@justdial.com,tejas.solanki@justdial.com,linux@justdial.com

echo -e "Server Hardening Done on $SYSTEM_IP Serial = ${SERI}  \n\nOS=${OSS} \n\nVER=${OSS_VER} \n\nDMICODE+${DMI} \n\nDate=${DDATE} \n\n Last login details \n ${LAST} \n\n ===  DISK Details \n\n ${DISKK}" | mail -s "New Installation on $SYSTEM_IP $HOSTNAME  $SERI done by $NAME" sachinthore@justdial.com,bhavesh.prajapati@justdial.com,linux@justdial.com

clear; echo "GENTLE REMINDER - PLZ. RESTART SERVER LATER";  sleep 10; clear
}

filebeat_setup_8_8_2(){
echo "Settingup filebeat 8.8.2 as an additional Option.."
curl -s http://172.29.0.123/download/INVENTORY/filebeat_8.8.2_for_syslog_deploy.sh | sudo bash -s
}

repo_fix(){
curl -s http://172.29.0.123/download/enable_centos7_repo.sh | bash -s 
}

ldap_client_install () {
echo "Installing Ldap Clinet additionaly."
#curl http://172.29.0.123/download/openldap_setup/ldapclient_setup_sssd_centos7.sh | sudo bash -x
wget -q -O /tmp/ldapclient_setup_sssd_centos7_new.sh http://172.29.0.123/download/openldap_setup/ldapclient_setup_sssd_centos7_new.sh && sudo sh /tmp/ldapclient_setup_sssd_centos7_new.sh
proceed_further
}

nginx_install () {
echo "Installing Nginx from RHEL 7 Custom Channel"
yum -y install nginx
}

mariadb_install () {
echo "Installing MariaDB from RHEL 7 Channel"
echo "MariaDB version 5.5.37-7"
yum -y install mariadb-server-5.5.37-1.el7_0
if [ ! -d /var/log/mysql ]; then mkdir -p /var/log/mysql; fi
if [ ! -d /var/lib/SQL ]; then mkdir -p /var/lib/SQL; fi
## Mysql logrotate - to do
mv /etc/logrotate.d/mysql $WORKING_DIR; cp $DOWNLOAD_DIR/logrotate/logrotate_mysql /etc/logrotate.d/mysql
} 

sphinx_install () {
echo " Installing Sphinx 2.2.4 from sphinxsearch.com "
yum -y install sphinx
}

XZ_log_structure () {
echo "Creating Nginx Logs and container logs Dir Streture For .XZ logs storage."

mkdir -p /var/log/nginx/BACKUP/Day{01..31}/{NGinx,Container}
chown -R web_backup.root /var/log/nginx/BACKUP/
chmod 755 -R /var/log/nginx/BACKUP/


mkdir -p /var/log/nginx/BACKUP_PAIDLOG/Day{01..31}/{NGinx,Container}
chown -R web_backup.root /var/log/nginx/BACKUP_PAIDLOG/
chmod 755 -R /var/log/nginx/BACKUP_PAIDLOG/
}

nic_bonding () {
echo " THIS IS ON TESTING - PLZ VERIFY ONCE MANUALLY AND ENSURE THAT DRAC IS AVAILABLE!!! :)"
DEF_ROUTE=`/sbin/route -n | awk '$1 == "0.0.0.0" { print $2 }'`
DEF_PREFIX=`/sbin/ip route | grep src | awk '{print $1}' | cut -d'/' -f2`
echo " Please enter below the two interfaces to be configured for NIC bonding "
echo " Specify first interface e.g. eth0 "
read NIC1
echo " Specify second interface e.g. eth1 "
read NIC2
if [ -z $NIC1 ] || [ -z $NIC2 ]
then
echo " Missing values for interface names. Exiting... "
sleep 5
else
echo " Changing interface values in ifcfg-$NIC1 & ifcfg-$NIC2 "

/bin/systemctl stop NetworkManager.service
/bin/systemctl disable NetworkManager.service

for nic in $NIC1 $NIC2
do
echo -e "TYPE=Ethernet" >> /etc/sysconfig/network-scripts/ifcfg-$nic
echo -e "DEFROUTE=yes" >> /etc/sysconfig/network-scripts/ifcfg-$nic
#echo -e "IPV4_FAILURE_FATAL=no" >> /etc/sysconfig/network-scripts/ifcfg-$nic
#echo -e "IPV6INIT=yes" >> /etc/sysconfig/network-scripts/ifcfg-$nic
#echo -e "IPV6_AUTOCONF=yes" >> /etc/sysconfig/network-scripts/ifcfg-$nic
#echo -e "IPV6_DEFROUTE=yes" >> /etc/sysconfig/network-scripts/ifcfg-$nic
#echo -e "IPV6_FAILURE_FATAL=no" >> /etc/sysconfig/network-scripts/ifcfg-$nic
#echo -e "IPV6_PEERDNS=yes" >> /etc/sysconfig/network-scripts/ifcfg-$nic
#echo -e "IPV6_PEERROUTES=yes" >> /etc/sysconfig/network-scripts/ifcfg-$nic
#echo -e "IPV6_PRIVACY=no" >> /etc/sysconfig/network-scripts/ifcfg-$nic
sed -i 's/^HWADDR/#HWADDR/g' /etc/sysconfig/network-scripts/ifcfg-$nic
sed -i 's/^NM_CONTROLLED/#NM_CONTROLLED/g' /etc/sysconfig/network-scripts/ifcfg-$nic
sed -i '/^IPADDR.*/d' /etc/sysconfig/network-scripts/ifcfg-$nic
sed -i '/^NETMASK.*/d' /etc/sysconfig/network-scripts/ifcfg-$nic
sed -i '/^GATEWAY.*/d' /etc/sysconfig/network-scripts/ifcfg-$nic
sed -i '/^DNS1.*/d' /etc/sysconfig/network-scripts/ifcfg-$nic
sed -i '/^DNS2.*/d' /etc/sysconfig/network-scripts/ifcfg-$nic
sed -i '/^PEERDNS.*/d' /etc/sysconfig/network-scripts/ifcfg-$nic
sed -i 's/^NETWORK/#NETWORK/g' /etc/sysconfig/network-scripts/ifcfg-$nic
sed -i 's/BOOTPROTO.*/BOOTPROTO=none/g' /etc/sysconfig/network-scripts/ifcfg-$nic
sed -i 's/ONBOOT=no/ONBOOT=yes/g' /etc/sysconfig/network-scripts/ifcfg-$nic
echo -e "MASTER=bond0\nSLAVE=yes" >> /etc/sysconfig/network-scripts/ifcfg-$nic
done

echo " Configuing ifcfg-bond0 "
echo -e "DEVICE=bond0\nNAME=bond0\nTYPE=Bond\nBONDING_MASTER=yes\nIPADDR=$SYSTEM_IP\nONBOOT=yes\nPREFIX=$DEF_PREFIX\nGATEWAY=${DEF_ROUTE}\nBOOTPROTO=none\nBONDING_OPTS=\"mode=1 miimon=200\"" > /etc/sysconfig/network-scripts/ifcfg-bond0
echo "alias bond0 bonding" > /etc/modprobe.d/bonding.conf
fi

echo " Restart network service or restart server "
sleep 10
}

change_sat_reg () {
echo "Option Not Available"
#SAT_SRV=`grep serverURL= /etc/sysconfig/rhn/up2date | awk -F "/" '{ print $3 }'`
#echo -e " This system is currently registered with \033[31m$SAT_SRV \033[0m"
#echo " Change Satellite Server Registration "
#echo " A) Change from RHN Satellite to Spacewalk "
#echo " B) Change from Spacewalk to RHN Satellite "
#read satellitechoice
#case $satellitechoice in
#A|a) spacewalk_reg ;;
#B|b) satellite_reg ;;
#esac
}

#----------------------------------------------------------------------------------

while true
do
clear
###################################################################################
### RHEL 7 Server Software Configuration 
###################################################################################
echo " JustDial - RHEL 7 Server Configuration Options "
echo -e "\n\n \e[4;34m Please do not use the options in RED. Not yet ready for RHEL 7 \e[0m \n\n"
echo " 1) Basic Configuration Changes "
echo -e " 2) Nginx Install [Just Installs Nginx :)]"
echo -e " 3) MariaDB Install "
echo " 4) Sphinx Install "
echo -e "\e[0;31m 5) NIC Bonding \e[0m"
echo -e "\e[0;31m 6) Change Satellite Server Registration \e[0m"
echo -e "\e[0;31m 7) Run Audit Script \e[0m"
echo " 8) Install ldap Client"
echo " 9) XZ_log_structure"
echo " 10) filebeat_setup_8_8_2"
echo " 11) repo_fix"
echo " 12) Exit"
echo " Plz. input your choice ( 1 - 12 )"
read installchoice
case $installchoice in
1) mandatory_config ;;
2) nginx_install ;;
3) mariadb_install ;;
4) sphinx_install ;;
5) nic_bonding ;;
6) change_sat_reg ;;
7) wget -O $DOWNLOAD_DIR/audit_check.sh --user admin1 --password justdial@999 http://172.29.0.123/process/SYDNEY/audit_check.sh; chmod +x $DOWNLOAD_DIR/audit_check.sh; $DOWNLOAD_DIR/audit_check.sh ;;
8) ldap_client_install ;;
9) XZ_log_structure ;;
10) filebeat_setup_8_8_2 ;;
11) repo_fix ;;
12) echo "Exiting install script on User input"; exit 1;;
esac
done
