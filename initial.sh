#!/bin/bash

install_prerequisities() {

	echo -e "\nBefore we install any prerequisities, this script will remove many rpm groups and packages to make the system \"cleaner\"."
	read -p "Are you sure you want to remove them? Y/N:" -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		yum groupremove "E-mail server" "Graphical Administration Tools" "Perl Support" "Network file system client" "Web Server" "PHP Support" "PostgreSQL Database server" "MySQL Database server"
		yum remove epel* rpmforge* webmin* virtualmin* php* perl* mysql* postgre*
	fi
	
	yum install wget mlocate subversion perl at git man

}

set_repos() {

        if [ ! -f /etc/yum.repos.d/rpmforge.repo ]
                then echo -e "RPMForge"
                yum -q -y localinstall --nogpgcheck http://packages.sw.be/rpmforge-release/rpmforge-release-0.5.3-1.el6.rf.x86_64.rpm
                else echo -e "RPMForge repository already set"
        fi

        if [ ! -f /etc/yum.repos.d/epel.repo ]
                then echo -e "EPEL"
                yum -q -y localinstall --nogpgcheck http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm
                else echo -e "EPEL repository already set"
        fi

        if [ ! -f /etc/yum.repos.d/rpmfusion-free-updates.repo ]
                then echo -e "RPMFusion"
                yum -q -y localinstall --nogpgcheck http://download1.rpmfusion.org/free/el/updates/6/i386/rpmfusion-free-release-6-1.noarch.rpm
                yum -q -y localinstall --nogpgcheck http://download1.rpmfusion.org/nonfree/el/updates/6/i386/rpmfusion-nonfree-release-6-1.noarch.rpm
                else echo -e "RPMFusion repository already set"
        fi

        if [ ! -f /etc/yum.repos.d/atomic.repo ]
                then echo -e "Atomic"
                wget -q -O - http://www.atomicorp.com/installers/atomic | sh
                else echo -e "Atomic repository already set"
        fi
        
        echo -e "Disabling added repositories"
	sed -i "s@^enabled.*@enabled=0@" /etc/yum.repos.d/atomic*.repo
	sed -i "s@^enabled.*@enabled=0@" /etc/yum.repos.d/epel*.repo
	sed -i "s@^enabled.*@enabled=0@" /etc/yum.repos.d/rpmforge*.repo
	sed -i "s@^enabled.*@enabled=0@" /etc/yum.repos.d/rpmfusion*.repo

	echo -e "Done."

}


install_virtualmin() {

	wget -q -O /tmp/install.sh http://software.virtualmin.com/gpl/scripts/install.sh
	sh /tmp/install.sh -f
	rm -f /tmp/install.sh
	
	echo -e "Installing Stress-Free Webmin theme"
	wget -q -O - https://webmin-theme-stressfree.googlecode.com/files/theme-stressfree-2.10.tar.gz | tar xzf - -C /usr/libexec/webmin
	echo "theme-stressfree" > /usr/libexec/webmin/defaulttheme
	sed -i "s@^theme.*@theme=theme-stressfree@" /etc/webmin/config

	########################################################
	# Instruct to perform initial set up of Virtualmin GPL #
	########################################################

	IP_ADDR=$(ip a s eth0 | grep 'inet ' | cut -d/ -f1 | awk '{ print $2 }')
	echo -e "\n########################################"
	echo -e "#"
	echo -e "#             IMPORTANT!!!"
	echo -e "#"
	echo -e "# Please navigate to following address"
	echo -e "#  in your browser and perform initial"
	echo -e "#   set up of Virtualmin GPL:"
	echo -e "#"
	echo -e "#   https://${HOSTNAME}:10000/"
	echo -e "#"
	echo -e "#               or"
	echo -e "#"
	echo -e "#   https://${IP_ADDR}:10000/"
	echo -e "#"
	echo -e "#######################################"

}


update_install() {

	echo -e "Install common packages"
	yum --enablerepo=atomic,epel,rpmforge install php-mcrypt php-pecl-imagick php-pecl-apc php-pecl-memcache phpMyAdmin memcached htop mytop optipng

	echo -e "Enable memcached to start on boot"
	chkconfig memcached on
	
	if [ ! -f /etc/yum.repos.d/mod-pagespeed.repo ]
		then echo -e "\nInstall of mod_pagespeed"
		rpm --import https://dl-ssl.google.com/linux/linux_signing_key.pub
		yum -q -y localinstall https://dl-ssl.google.com/dl/linux/direct/mod-pagespeed-stable_current_$(uname -i).rpm
		else echo -e "\nmod_pagespeed repository already set"
	fi

	echo -e "Updating system"
	yum update

	echo -e "Update PHP and MySQL from Atomic repository"
	yum --enablerepo=atomic update php mysql

}


system_settings() {

#################################################
##                                             ##
##  These settings are taken from CentOS wiki: ##
##                                             ##
## http://wiki.centos.org/HowTos/OS_Protection ##
##                                             ##
#################################################

	##########################
	# Basic System behaviour #
	##########################
	
	echo -e "Disable the key check for interactive mode"
	sed -i "s@^PROMPT.*@PROMPT=no@" /etc/sysconfig/init

	echo -e "Limit number of TTYs"
	sed -i "s@\[1-6\]@\[1\]@" /etc/sysconfig/init

	echo -e "Prompt for password on single-user mode"
	sed -i "s@^SINGLE.*@SINGLE=/sbin/sulogin@" /etc/sysconfig/init

	echo -e "Disable shutdown via Ctrl+Alt+Del"
	sed -i "s@^start@#start@" /etc/init/control-alt-delete.conf

	echo -e "Change default password length requirement"
	sed -i "s@pam_cracklib.so try@pam_cracklib.so minlen=9 try@" /etc/pam.d/system-auth

	echo -e "Use sha512 instead of md5 for password protection"
	authconfig --passalgo=sha512 --update

	########################
	# Restrict cron and at #
	########################

	echo -e "Restrict 'cron' and 'at' to root only"
	if [ ! -f /etc/cron.allow ]
		then touch /etc/cron.allow
	fi
	chmod 600 /etc/cron.allow
	awk -F: '{ print $1 }' /etc/passwd | grep -v root > /etc/cron.deny

	if [ ! -f /etc/at.allow ]
		then touch /etc/at.allow
	fi
	chmod 600 /etc/at.allow
	awk -F: '{ print $1 }' /etc/passwd | grep -v root > /etc/at.deny

	##################################
	# Directory and file permissions #
	##################################

	echo -e "Set up important directory and file permissions"
	chmod 700 /root
	chmod 600 /etc/rsyslog.conf
	chmod 640 /etc/security/access.conf
	chmod 600 /etc/sysctl.conf
	chmod -R 700 /etc/skel
	chmod 740 /etc/rc.d/init.d/iptables
	chmod 740 /sbin/iptables
	chmod 700 /var/log/audit

	################
	# Delete users #
	################

	echo -e "User clean-up"
	for USER in	shutdown\
			halt\
			games\
			operator\
			gopher
	do userdel ${USER}
	done

	############################
	# Blacklist kernel modules #
	############################

	echo -e "Blacklisting SCSI fcoe kernel modules"
	for FCOE in $(find /lib/modules/`uname -r`/kernel/drivers/scsi/fcoe -name "*.ko" -type f)
	do
		echo blacklist ${FCOE} >> /etc/modprobe.d/blacklist-fcoe.conf
	done

	echo -e "Blacklisting USB Mass Storage modules"
	for USBS in $(find /lib/modules/`uname -r`/kernel/drivers/usb/storage -name "*.ko" -type f)
	do
		echo blacklist ${USBS} >> /etc/modprobe.d/blacklist-usbstorage.conf
	done

	echo -e "Blacklisting Wireless kernel modules"
	for WIFI in $(find /lib/modules/$(uname -r)/kernel/drivers/net/wireless -name "*.ko" -type f)
	do
		echo blacklist ${WIFI} >> /etc/modprobe.d/blacklist-wireless.conf
	done

	###########################
	# Sysctl network security #
	###########################

	echo -e "Hardening Sysctl network settings"
	# Packet forwarding
	sysctl -w net.ipv4.ip_forward=0
	# ICMP redirects
	sysctl -w net.ipv4.conf.all.send_redirects=0
	sysctl -w net.ipv4.conf.default.send_redirects=0
	sysctl -w net.ipv4.conf.all.accept_redirects=0
	sysctl -w net.ipv4.conf.all.secure_redirects=0
	sysctl -w net.ipv4.conf.default.accept_redirects=0
	sysctl -w net.ipv4.conf.default.secure_redirects=0
	# SYN backlog size - double the size
	sysctl -w net.ipv4.tcp_max_syn_backlog=2048
	# PING broadcasts
	sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
	# Source routing ability
	sysctl -w net.ipv4.conf.all.accept_source_route=0
	sysctl -w net.ipv4.conf.default.accept_source_route=0
	# Log Martian packets
	sysctl -w net.ipv4.conf.all.log_martians=1
	# Ignore bogus ICMP error responses
	sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
	# SYN flood attacks protection
	sysctl -w net.ipv4.tcp_syncookies=1
	# Drop packets from wrong interface (will be logged as Martian)
	sysctl -w net.ipv4.conf.all.rp_filter=1
	sysctl -w net.ipv4.conf.default.rp_filter=1
	# No timestamps
	sysctl -w net.ipv4.tcp_timestamps=0

	##########################
	# TCP wrapper - SSH only #
	##########################

	echo -e "Permit SSH only using TCP wrapper"
	echo "ALL:ALL" >> /etc/hosts.deny
	echo "sshd:ALL" >> /etc/hosts.allow

	##########################################
	# Disconnect idle users after 15 minutes #
	##########################################

	echo -e "\nDisconnect idle users after 15 minutes"
	cat > /etc/profile.d/idle-users.sh << EOF
readonly TMOUT=900
readonly HISTFILE
EOF
	chmod +x /etc/profile.d/idle-users.sh

}


ssh_settings() {

#######################################################
##                                                   ##
##     These settings are taken from CentOS wiki:    ##
##                                                   ##
## http://wiki.centos.org/HowTos/Network/SecuringSSH ##
##                                                   ##
#######################################################

#	echo -e "\nDisable Root logins"
#	sed -i "s@^#PermitRootLogin.*@PermitRootLogin no@" /etc/ssh/sshd_config
	
#	echo -e "\nLimit user logins"
#	sed -i "s@.*AllowUsers.*@AllowUsers admin@" /etc/ssh/sshd_config

	echo -e "Disable Protocol 1"
	sed -i "s@.*Protocol.*@Protocol 2@" /etc/ssh/sshd_config

	echo -e "Use a Non-Standard Port"
	PORT=$(shuf -i 40000-65000 -n 1)
	sed -i "s@#Port.*@Port ${PORT}@" /etc/ssh/sshd_config

	echo -e "Open port ${PORT} in the firewall"
	sed -i "/dport ssh/d" /etc/sysconfig/iptables
	sed -i "s@dport 22@dport ${PORT}@" /etc/sysconfig/iptables

	echo -e "Apply IPTables settings"
	service iptables restart

#	echo -e "Disable password authentication forcing use of keys"
#	sed -i "s@.*PasswordAuthentication yes.*@PasswordAuthentication no@" /etc/ssh/sshd_config

	echo -e "Create network login banner - /etc/issue"
	cat > /etc/issue << EOF



        STOP:

           ACCESS TO THIS COMPUTER IS PROHIBITED UNLESS AUTHORIZED.
        USE OF THIS COMPUTER SYSTEM  CONSTITUTES CONSENT TO MONITORING
        OF THIS SYSTEM.  EVIDENCE OF UNAUTHORIZED USE COLLECTED DURING
        MONITORING MAY BE USED FOR  ADMINISTRATIVE, CRIMINAL, OR OTHER
        ADVERSE ACTION.
        IF YOU ARE NOT AUTHORIZED DISCONNECT NOW. ACCESS FOR ANY OTHER
        REASON IS  AN ILLEGAL  ACT AND  MAY BE SUBJECT TO  CIVIL RIGHT
        ACTIONS!



EOF

	echo -e "Enable network login banner in SSH"
	sed -i "s@^#Banner.*@Banner /etc/issue@" /etc/ssh/sshd_config

	echo -e "Enable agent forwarding"
	sed -i "s@^#AllowAgentForwarding.*@AllowAgentForwarding yes@" /etc/ssh/sshd_config

	echo -e "Enable TCP forwarding"
	sed -i "s@^#AllowTcpForwarding.*@AllowTcpForwarding yes@" /etc/ssh/sshd_config

	echo -e "Server key bits bigger"
	sed -i "s@^#ServerKeyBits.*@ServerKeyBits 2048@" /etc/ssh/sshd_config
	
	echo -e "Remove old server keys\n"
	rm -vf /etc/ssh/ssh_host*

	echo -e "Enable TCPKeepAlive"
	sed -i "s@^#TCPKeepAlive.*@TCPKeepAlive yes@" /etc/ssh/sshd_config

	echo -e "Set ClientAliveInterval"
	sed -i "s@^#ClientAliveInterval.*@ClientAliveInterval 30@" /etc/ssh/sshd_config

	echo -e "Permit tunneling"
	sed -i "s@^#PermitTunnel.*@PermitTunnel yes@" /etc/ssh/sshd_config

	echo -e "Restrict max number of retries"
	sed -i "s@^#MaxAuthTries.*@MaxAuthTries 3@" /etc/ssh/sshd_config

	echo -e "Restart sshd to apply changes\n"
	service sshd restart

	################################
	# Print connection information #
	################################

	echo -e "\n#######################################"
	echo -e "#"
	echo -e "# To connect to system use following:"
	echo -e "#"
	echo -e "#   ssh -p ${PORT} root@${IP_ADDR}"
	echo -e "#"
	echo -e "#######################################"

}


mysql_settings() {

	echo -e "Use the newest configuration file"
	mv /etc/my.cnf /etc/my.cnf.rpmold
	mv /etc/my.cnf.rpmnew /etc/my.cnf

	echo -e "Bind MySQL to localhost only"
	BINDLOCAL=$(grep -c bind-address /etc/my.cnf)
	if [ ${BINDLOCAL} = 0 ]
		then sed -i '/\[mysqld\]/a \
bind-address=localhost' /etc/my.cnf
		else sed -i "s@.*bind-address.*@bind-address=localhost@" /etc/my.cnf
	fi

	echo -e "Restart mysqld to apply changes"
	service mysqld restart

}


apache_settings() {

	echo -e "Set Server HTTP response header to Prod"
	sed -i "s@^ServerTokens.*@ServerTokens Prod@" /etc/httpd/conf/httpd.conf

	echo -e "Enable keep-alive connections"
	sed -i "s@^KeepAlive O.*@KeepAlive On@" /etc/httpd/conf/httpd.conf
	
	echo -e "Enable transfer compression"
	cat > /etc/httpd/conf.d/deflate.conf << EOF
<IfModule mod_deflate.c>
	<FilesMatch "\.(js|css|x?html?|htm|php|xml)$">
        	SetOutputFilter DEFLATE
	</FilesMatch>
</IfModule>
EOF

	echo -e "Enable expire headers"
	cat > /etc/httpd/conf.d/expires.conf << EOF
ExpiresActive On
	<FilesMatch "\.(jpg|jpeg|gif|png|ico|js|css)$">
		Header unset Etag
		Header set Cache-control "public, max-age=2592000"
	</FilesMatch>
EOF

#	echo -e ""
	
#	echo -e ""

}


php_settings() {

	echo -e "Do not expose PHP version"
	sed -i "s@.*expose_php =.*@expose_php = Off@" /etc/php.ini

	echo -e "Set correct timezone"
	TIMEZONE=$(cat /etc/sysconfig/clock | cut -d\" -f2)
	sed -i "s@.*date.timezone =.*@date.timezone = ${TIMEZONE}@" /etc/php.ini

	echo -e "Set correct cookie domain"
	sed -i "s@.*session.cookie_domain =.*@session.cookie_domain = ${HOSTNAME}@" /etc/php.ini

}

print_usage() {

cat << EOF

Usage: $0 [-IRVUOSMAP]

This script performs initial setting of the system and common services
after fresh install of CentOS minimal Linux distribution.

OPTIONS:

  -I   Install prerequisities
  -R   Set up repositories
  -V   Install Virtualmin GPL
  -U   Update system and instal additional packages
  -O   Harden Operating System settings
  -S   Secure OpenSSH server settings
  -M   Tweak MySQL server settings
  -A   Tweak Apache server settings
  -P   Tweak PHP settings
  
EOF

exit 1

}

## Run it ##

if [ $# -eq 0 ]
	then print_usage
fi

OPTIONS="IRVUOSMAP"

while getopts ${OPTIONS} optname
do
	case "${optname}" in
		"I")
			echo -e "\nInstalling prerequisities"
			install_prerequisities
			;;
		"R")
			echo -e "\nSetting up repositories"
			set_repos
			;;
		"V")
			echo -e "\nInstalling Virtualmin GPL"
			install_virtualmin
			;;
		"U")
			echo -e "\nUpdate system and install additional packages"
			update_install
			;;
		"O")
			echo -e "\nHardening Operating system settings"
			system_settings
			;;
		"S")
			echo -e "\nSecuring OpenSSH server settings"
			ssh_settings
			;;
		"M")
			echo -e "\nMySQL server settings"
			mysql_settings
			;;
		"A")
			echo -e "\nApache server settings"
			apache_settings
			;;
		"P")
			echo -e "\nPHP settings"
			php_settings
			;;
		"?")
			print_usage
			;;
#		":")
#			echo "No argument value for option $OPTARG"
#			;;
#		*)
# Should not occur
#			echo "Unknown error while processing options"
#			;;
	esac
done

