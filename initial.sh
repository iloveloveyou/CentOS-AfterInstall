#!/bin/bash

function install_prerequisities {

	echo -e "\nInstalling prerequisities"
	yum -q -y install wget mlocate subversion yum-plugin-priorities perl at

}

function set_repos {

        if [ ! -f /etc/yum.repos.d/rpmforge.repo ]
                then echo -e "\nSetting up RPMForge repository"
                yum -q -y localinstall --nogpgcheck http://packages.sw.be/rpmforge-release/rpmforge-release-0.5.3-1.el6.rf.x86_64.rpm
                else echo -e "\nRPMForge repository already set"
        fi

        if [ ! -f /etc/yum.repos.d/epel.repo ]
                then echo -e "\nSetting up EPEL repository"
                yum -q -y localinstall --nogpgcheck http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm
                else echo -e "\nEPEL repository already set"
        fi

        if [ ! -f /etc/yum.repos.d/rpmfusion-free-updates.repo ]
                then echo -e "\nSetting up RPMFusion repository"
                yum -q -y localinstall --nogpgcheck http://download1.rpmfusion.org/free/el/updates/6/i386/rpmfusion-free-release-6-1.noarch.rpm
                yum -q -y localinstall --nogpgcheck http://download1.rpmfusion.org/nonfree/el/updates/6/i386/rpmfusion-nonfree-release-6-1.noarch.rpm
                else echo -e "\nRPMFusion repository already set"
        fi

        if [ ! -f /etc/yum.repos.d/atomic.repo ]
                then echo -e "\nSetting up Atomic repository"
                wget -q -O - http://www.atomicorp.com/installers/atomic | sh
                else echo -e "\nAtomic repository already set"
        fi
        
        echo -e "\nDisabling added repositories"
	sed -i 's/^enabled.*$/enabled=0/' /etc/yum.repos.d/atomic*.repo
	sed -i 's/^enabled.*$/enabled=0/' /etc/yum.repos.d/epel*.repo
	sed -i 's/^enabled.*$/enabled=0/' /etc/yum.repos.d/rpmforge*.repo
	sed -i 's/^enabled.*$/enabled=0/' /etc/yum.repos.d/rpmfusion*.repo

}


function install_virtualmin {

	echo -e "\nInstalling Virtualmin GPL"
	wget -q -O install.sh http://software.virtualmin.com/gpl/scripts/install.sh; sh install.sh -f

	echo -e "\nUpdate from Atomic repository"
	yum -q -y --enablerepo=atomic update php mysql

}


function system_settings {

	echo -e "\nDisable the key check for interactive mode"
	sed -i 's/^PROMPT.*/PROMPT=no/' /etc/sysconfig/init

	echo -e "\nLimit number of TTYs"
	sed -i 's/\[1-6\]/\[1\]/' /etc/sysconfig/init

	echo -e "\nPrompt for password on single-user mode"
	sed -i 's/^SINGLE.*/SINGLE=\/sbin\/sulogin/' /etc/sysconfig/init

	echo -e "\nDisable shutdown via Ctrl+Alt+Del"
	sed -i 's/^start/#start/' /etc/init/control-alt-delete.conf

	echo -e "\nChange default password length requirement"
	sed -i 's/pam_cracklib.so/pam_cracklib.so\ minlen=9/' /etc/pam.d/system-auth

	echo -e "\nDisconnect idle users after 15 minutes"
	cat > /etc/profile.d/idle-users.sh << EOF
	readonly TMOUT=900
	readonly HISTFILE
EOF

	chmod +x /etc/profile.d/idle-users.sh

	echo -e "\nRestrict 'cron' and 'at' to root only"
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

}


function network_settings {

	# Packet forwarding
	sysctl -w net.ipv4.ip_forward = 0
	# ICMP redirects
	sysctl -w net.ipv4.conf.all.send_redirects = 0
	sysctl -w net.ipv4.conf.default.send_redirects = 0
	sysctl -w net.ipv4.conf.all.accept_redirects = 0
	sysctl -w net.ipv4.conf.all.secure_redirects = 0
	sysctl -w net.ipv4.conf.default.accept_redirects = 0
	sysctl -w net.ipv4.conf.default.secure_redirects = 0
	# SYN backlog size - double the size
	sysctl -w net.ipv4.tcp_max_syn_backlog = 2048
	# PING broadcasts
	sysctl -w net.ipv4.icmp_echo_ignore_broadcasts = 1
	# Source routing ability
	sysctl -w net.ipv4.conf.all.accept_source_route = 0
	sysctl -w net.ipv4.conf.default.accept_source_route = 0
	# Log Martian packets
	sysctl -w net.ipv4.conf.all.log_martians = 1
	# Ignore bogus ICMP error responses
	sysctl -w net.ipv4.icmp_ignore_bogus_error_responses = 1
	# SYN flood attacks protection
	sysctl -w net.ipv4.tcp_syncookies = 1
	# Drop packets from wrong interface (will be logged as Martian)
	sysctl -w net.ipv4.conf.all.rp_filter = 1
	sysctl -w net.ipv4.conf.default.rp_filter = 1
	# No timestamps
	sysctl -w net.ipv4.tcp_timestamps = 0
	
	echo "ALL:ALL" >> /etc/hosts.deny
	echo "sshd:ALL" >> /etc/hosts.allow

}


function blacklist_modules {

	echo -e "\nWireless kernel modules - disabling"
	for WIFI in $(find /lib/modules/`uname -r`/kernel/drivers/net/wireless -name "*.ko" -type f)
	do
		echo blacklist ${WIFI} >> /etc/modprobe.d/blacklist-wireless.conf
	done

	echo -e "\nSCSI fcoe kernel modules - disabling"
	for FCOE in $(find /lib/modules/`uname -r`/kernel/drivers/scsi/fcoe -name "*.ko" -type f)
	do
		echo blacklist ${FCOE} >> /etc/modprobe.d/blacklist-fcoe.conf
	done

}


function ssh_settings {

#	echo -e "\nDisable Root logins"
#	sed -i 's/^#PermitRootLogin\ yes/PermitRootLogin\ no/' /etc/ssh/sshd_config
	
#	echo -e "\nLimit user logins"
#	sed -i 's/.*AllowUsers.*/AllowUsers\ admin/' /etc/ssh/sshd_config

	echo -e "\nDisable Protocol 1"
	sed -i 's/.*Protocol.*/Protocol\ 2/' /etc/ssh/sshd_config

	echo -e "\nUse a Non-Standard Port"
        PORT=$(echo $((RANDOM%55000+40000)))
        sed -i "s/#Port.*/Port\ ${PORT}/" /etc/ssh/sshd_config
        
        echo -e "\nOpen the port ${PORT} in the firewall"
        sed -i '/dport\ ssh/d' /etc/sysconfig/iptables
        sed -i "s/dport\ 22/dport\ ${PORT}/" /etc/sysconfig/iptables
        
        echo -e "\nApply IPTables settings"
        service iptables restart
        
        IP_ADDR=$(ip a s eth0 | grep 'inet ' | cut -d/ -f1 | awk '{ print $2 }')
        
        echo -e "\n#######################################"
        echo -e "#"
        echo -e "# To connect to system use following:"
        echo -e "#"
        echo -e "#   ssh -p ${PORT} root@${IP_ADDR}"
        echo -e "#"
        echo -e "#######################################"

	echo -e "\nNetwork login banner - /etc/issue"
	cat > /etc/issue << EOF



        STOP:

           ACCESS TO THIS COMPUTER IS PROHIBITED UNLESS AUTHORIZED.
        USE OF THIS COMPUTER SYSTEM  CONSTITUTES CONSENT  TO MONITORING
        OF THIS SYSTEM.  EVIDENCE OF  UNAUTHORIZED USE COLLECTED DURING
        MONITORING MAY BE USED FOR  ADMINISTRATIVE,  CRIMINAL, OR OTHER
        ADVERSE ACTION.
        IF YOU ARE NOT AUTHORIZED, DISCONNECT NOW. ACCESS FOR ANY OTHER
        REASON IS  AN ILLEGAL  ACT AND  MAY BE  SUBJECT TO  CIVIL RIGHT
        ACTIONS!



EOF

	echo -e "\nEnable network login banner in SSH"
	sed -i 's/^#Banner.*/Banner \/etc\/issue/' /etc/ssh/sshd_config

        echo -e "\nEnable agent forwarding"
	sed -i 's/^#AllowAgentForwarding.*/AllowAgentForwarding\ yes/' /etc/ssh/sshd_config

        echo -e "\nEnable TCP forwarding"
	sed -i 's/^#AllowTcpForwarding.*/AllowTcpForwarding\ yes/' /etc/ssh/sshd_config

	echo -e "\nServer key bits bigger"
	sed -i 's/^#ServerKeyBits.*/ServerKeyBits\ 2048/' /etc/ssh/sshd_config
	
	echo -e "\nRemove old server keys\n"
	rm -vf /etc/ssh/ssh_host*

	echo -e "\nEnable TCPKeepAlive"
	sed -i 's/^#TCPKeepAlive.*/TCPKeepAlive\ yes/' /etc/ssh/sshd_config

	echo -e "\nSet ClientAliveInterval"
	sed -i 's/^#ClientAliveInterval.*/ClientAliveInterval\ 30/' /etc/ssh/sshd_config
	
	echo -e "\nPermit tunneling"
	sed -i 's/^#PermitTunnel.*/PermitTunnel\ yes/' /etc/ssh/sshd_config

	echo -e "\nRestrict max number of retries"
	sed -i 's/^#MaxAuthTries.*/MaxAuthTries\ 3/' /etc/ssh/sshd_config

	echo -e "\nRestarting sshd to apply changes\n"
	service sshd restart

}

function mysqld_settings {

	echo -e "\nBind MySQL to localhost only"

	BINDLOCAL=$(grep -c bind-address /etc/my.cnf)
	if [ ${BINDLOCAL} = 0 ]
		then sed -i '/\[mysqld\]/a \
bind-address=localhost' /etc/my.cnf
		else sed -i 's/.*bind-address.*/bind-address=localhost/' /etc/my.cnf
	fi

	echo -e "\nRestarting mysqld to apply changes\n"
	service mysqld restart

}


function set_permissions {

	echo -e "\nSet up important directory and file permissions"

	chmod 700 /root
	chmod 600 /etc/rsyslog.conf
	chmod 640 /etc/security/access.conf
	chmod 600 /etc/sysctl.conf
	chmod -R 700 /etc/skel
	chmod 740 /etc/rc.d/init.d/iptables
	chmod 740 /sbin/iptables
	chmod 700 /var/log/audit

}


function clean_users {

	echo -e "\nUser clean-up"
	for USER in	shutdown\
			halt\
			games\
			operator\
			ftp\
			gopher
	do userdel ${USER}
	done

}



#function fail2ban_install {

#	echo -e "\nFail2Ban installation"
#	yum -y --enablerepo=rpmforge install fail2ban
#	curl http://bkraft.fr/files/Configurations/fail2ban/jail.conf -o /etc/fail2ban/jail.conf
#	chkconfig fail2ban on
#	service fail2ban start

#}

function post_install {

	echo -e "\nInstalling common packages"
	yum -q -y --enablerepo=atomic,epel install php-mcrypt php-pecl-imagick phpMyAdmin memcached
	
	if [ ! -f /etc/yum.repos.d/mod-pagespeed.repo ]
		then echo -e "\nInstallation of mod_pagespeed"
		rpm --import https://dl-ssl.google.com/linux/linux_signing_key.pub
		yum -q -y localinstall https://dl-ssl.google.com/dl/linux/direct/mod-pagespeed-stable_current_$(uname -i).rpm
		else echo -e "\nmod_pagespeed repository already set"
	fi

	echo -e "\nUpdating system"
	yum -q -y update

}


## Run it ##

install_prerequisities

set_repos

install_virtualmin

system_settings

blacklist_modules

ssh_settings

mysqld_settings

set_permissions

clean_users

post_install



        IP_ADDR=$(ip a s eth0 | grep 'inet ' | cut -d/ -f1 | awk '{ print $2 }')
        
        echo -e "\n#######################################"
        echo -e "#"
        echo -e "# To connect to system use following:"
        echo -e "#"
        echo -e "#   ssh -p ${PORT} root@${IP_ADDR}"
        echo -e "#"
        echo -e "#######################################"


