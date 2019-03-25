banner () {
  echo "******************************************************"
  echo "[i] $1"
}

banner "System Info" && uname -a
banner "Available Compilers" && dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null
banner "Kernel information" && cat /proc/version 2>/dev/null
banner "Distribution information" && cat /etc/*-release 2>/dev/null
banner "Distribution information" && cat /etc/issue 2>/dev/null
banner "CPU information" && cat /proc/cpuinfo 2>/dev/null
banner "File system information" && df -a 2>/dev/null
banner "List available compilers" && dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null
banner "What's the kernel version? Is it 64-bit?" && rpm -q kernel 2>/dev/null && dmesg 2>/dev/null | grep Linux && ls /boot 2>/dev/null | grep vmlinuz-
banner "Environmental variables" && cat /etc/profile 2>/dev/null && cat /etc/bashrc 2>/dev/null && cat ~/.bash_profile 2>/dev/null && cat ~/.bashrc 2>/dev/null && cat ~/.bash_logout 2>/dev/null && env 2>/dev/null && set 2>/dev/null
banner "Is there a printer?" && lpstat -a 2>/dev/null
banner "What services are running?" && ps aux 2>/dev/null && ps -ef 2>/dev/null && cat /etc/services 2>/dev/null
banner "Which service(s) are been running by root?" && ps aux | grep root 2>/dev/null && ps -ef | grep root 2>/dev/null
banner "What applications are installed?" && ls -alh /usr/bin/ 2>/dev/null && ls -alh /sbin/ 2>/dev/null && dpkg -l 2>/dev/null && rpm -qa 2>/dev/null && ls -alh /var/cache/apt/archivesO 2>/dev/null && ls -alh /var/cache/yum/ 2>/dev/null
banner "Any of the service(s) settings misconfigured? Are any (vulnerable) plugins attached?" && cat /etc/syslog.conf 2>/dev/null cat /etc/chttp.conf 2>/dev/null && cat /etc/lighttpd.conf 2>/dev/null && cat /etc/cups/cupsd.conf 2>/dev/null && cat /etc/inetd.conf 2>/dev/null && cat /etc/apache2/apache2.conf 2>/dev/null && cat /etc/my.conf 2>/dev/null && cat /etc/httpd/conf/httpd.conf 2>/dev/null && cat /opt/lampp/etc/httpd.conf 2>/dev/null && ls -aRl /etc/ 2>/dev/null | awk '$1 ~ /^.*r.*/' 2>/dev/null

banner "Check 8: What jobs are scheduled?"
crontab -l 2>/dev/null
ls -alh /var/spool/cron 2>/dev/null
ls -al /etc/ 2>/dev/null | grep cron
ls -al /etc/cron* 2>/dev/null
cat /etc/cron* 2>/dev/null
cat /etc/at.allow 2>/dev/null
cat /etc/at.deny 2>/dev/null
cat /etc/cron.allow 2>/dev/null
cat /etc/cron.deny 2>/dev/null
cat /etc/crontab 2>/dev/null
cat /etc/anacrontab 2>/dev/null
cat /var/spool/cron/crontabs/root 2>/dev/null

banner "Check 9: Any plain text usernames and/or passwords?"
grep -i user [filename] 2>/dev/null
grep -i pass [filename] 2>/dev/null
grep -C 5 "password" [filename] 2>/dev/null
find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password" 2>/dev/null

banner "Check 10: What NIC(s) does the system have? Is it connected to another network?"
/sbin/ifconfig -a 2>/dev/null
cat /etc/network/interfaces 2>/dev/null
cat /etc/sysconfig/network 2>/dev/null

banner "Check 11: What are the network configuration settings? What can you find out about this network? DHCP server? DNS server? Gateway?"
cat /etc/resolv.conf 2>/dev/null
cat /etc/sysconfig/network 2>/dev/null
cat /etc/networks 2>/dev/null
iptables -L 2>/dev/null
hostname 2>/dev/null
dnsdomainname 2>/dev/null

banner "Check 12: What other users & hosts are communicating with the system?"
lsof -i 2>/dev/null
lsof -i :80 2>/dev/null
grep 80 /etc/services 2>/dev/null
netstat -antup 2>/dev/null
netstat -antpx 2>/dev/null
netstat -tulpn 2>/dev/null
chkconfig --list 2>/dev/null
chkconfig --list 2>/dev/null | grep 3:on
last 2>/dev/null
w 2>/dev/null

banner "Check 13: Whats cached? IP and/or MAC addresses"
arp -e 2>/dev/null
route 2>/dev/null
/sbin/route -nee 2>/dev/null


banner "Check 14: Who are you? Who is logged in? Who has been logged in? Who else is there? Who can do what?"
id 2>/dev/null
who 2>/dev/null
w 2>/dev/null
last 2>/dev/null
cat /etc/passwd | cut -d: -f1 2>/dev/null
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}' 2>/dev/null
awk -F: '($3 == "0") {print}' /etc/passwd 2>/dev/null
cat /etc/sudoers 2>/dev/null
sudo -l 2>/dev/null

banner "Check 15: What sensitive files can be found?"
cat /etc/passwd 2>/dev/null
cat /etc/group 2>/dev/null
cat /etc/shadow 2>/dev/null
ls -alh /var/mail/ 2>/dev/null

banner "Check 16: Anything interesting in the home directorie(s)? If it's possible to access"
ls -ahlR /root/ 2>/dev/null
ls -ahlR /home/ 2>/dev/null

banner "Check 17: Are there any passwords in; scripts, databases, configuration files or log files? Default paths and locations for passwords"
cat /var/apache2/config.inc 2>/dev/null
cat /var/lib/mysql/mysql/user.MYD 2>/dev/null
cat /root/anaconda-ks.cfg 2>/dev/null

banner "Check 18: What has the user being doing? Is there any password in plain text? What have they been edting?"
cat ~/.bash_history 2>/dev/null
cat ~/.nano_history 2>/dev/null
cat ~/.atftp_history 2>/dev/null
cat ~/.mysql_history 2>/dev/null
cat ~/.php_history 2>/dev/null

banner "Check 19: What user information can be found?"
cat ~/.bashrc 2>/dev/null
cat ~/.profile 2>/dev/null
cat /var/mail/root 2>/dev/null
cat /var/spool/mail/root 2>/dev/null

banner "Check 20: Can private-key information be found?"
cat ~/.ssh/authorized_keys 2>/dev/null
cat ~/.ssh/identity.pub 2>/dev/null
cat ~/.ssh/identity 2>/dev/null
cat ~/.ssh/id_rsa.pub 2>/dev/null
cat ~/.ssh/id_rsa 2>/dev/null
cat ~/.ssh/id_dsa.pub 2>/dev/null
cat ~/.ssh/id_dsa 2>/dev/null
cat /etc/ssh/ssh_config 2>/dev/null
cat /etc/ssh/sshd_config 2>/dev/null
cat /etc/ssh/ssh_host_dsa_key.pub 2>/dev/null
cat /etc/ssh/ssh_host_dsa_key 2>/dev/null
cat /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null
cat /etc/ssh/ssh_host_rsa_key 2>/dev/null
cat /etc/ssh/ssh_host_key.pub 2>/dev/null
cat /etc/ssh/ssh_host_key 2>/dev/null

banner "Check 21: Which configuration files can be written in /etc/? Able to reconfigure a service?"
ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null     # Anyone
ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null       # Owner
ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null    # Group
ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null        # Other
find /etc/ -readable -type f 2>/dev/null               # Anyone
find /etc/ -readable -type f -maxdepth 1 2>/dev/null   # Anyone

banner "Check 22: What can be found in /var/ ?"
ls -alh /var/log 2>/dev/null
ls -alh /var/mail 2>/dev/null
ls -alh /var/spool 2>/dev/null
ls -alh /var/spool/lpd 2>/dev/null
ls -alh /var/lib/pgsql 2>/dev/null
ls -alh /var/lib/mysql 2>/dev/null
cat /var/lib/dhcp3/dhclient.leases 2>/dev/null

banner "Check 23: Any settings/files (hidden) on website? Any settings file with database information?"
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/ 2>/dev/null
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
ls -alhR /var/www/html/ 2>/dev/null

banner "Check 24: Is there anything in the log file(s) (Could help with 'Local File Includes'!)"
cat /etc/httpd/logs/access_log 2>/dev/null
cat /etc/httpd/logs/access.log 2>/dev/null
cat /etc/httpd/logs/error_log 2>/dev/null
cat /etc/httpd/logs/error.log 2>/dev/null
cat /var/log/apache2/access_log 2>/dev/null
cat /var/log/apache2/access.log 2>/dev/null
cat /var/log/apache2/error_log 2>/dev/null
cat /var/log/apache2/error.log 2>/dev/null
cat /var/log/apache/access_log 2>/dev/null
cat /var/log/apache/access.log 2>/dev/null
cat /var/log/auth.log 2>/dev/null
cat /var/log/chttp.log 2>/dev/null
cat /var/log/cups/error_log 2>/dev/null
cat /var/log/dpkg.log 2>/dev/null
cat /var/log/faillog 2>/dev/null
cat /var/log/httpd/access_log 2>/dev/null
cat /var/log/httpd/access.log 2>/dev/null
cat /var/log/httpd/error_log 2>/dev/null
cat /var/log/httpd/error.log 2>/dev/null
cat /var/log/lastlog 2>/dev/null
cat /var/log/lighttpd/access.log 2>/dev/null
cat /var/log/lighttpd/error.log 2>/dev/null
cat /var/log/lighttpd/lighttpd.access.log 2>/dev/null
cat /var/log/lighttpd/lighttpd.error.log 2>/dev/null
cat /var/log/messages 2>/dev/null
cat /var/log/secure 2>/dev/null
cat /var/log/syslog 2>/dev/null
cat /var/log/wtmp 2>/dev/null
cat /var/log/xferlog 2>/dev/null
cat /var/log/yum.log 2>/dev/null
cat /var/run/utmp 2>/dev/null
cat /var/webmin/miniserv.log 2>/dev/null
cat /var/www/logs/access_log 2>/dev/null
cat /var/www/logs/access.log 2>/dev/null
ls -alh /var/lib/dhcp3/ 2>/dev/null
ls -alh /var/log/postgresql/ 2>/dev/null
ls -alh /var/log/proftpd/ 2>/dev/null
ls -alh /var/log/samba/ 2>/dev/null

#Note: auth.log, boot, btmp, daemon.log, debug, dmesg, kern.log, mail.info, mail.log, mail.warn, messages, syslog, udev, wtmp
#Note: http://www.thegeekstuff.com/2011/08/linux-var-log-files/

banner "Check 25: How are file-systems mounted?"
mount 2>/dev/null
df -h 2>/dev/null

banner "Check 26: Are there any unmounted file-systems?"
cat /etc/fstab 2>/dev/null

banner "Check 27: What 'Advanced Linux File Permissions' are used? Sticky bits, SUID & GUID"
find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
for i in `locate -r "bin$" 2>/dev/null;`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done    # Looks in 'common' places: /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin and any other *bin, for SGID or SUID (Quicker search)
# find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null

banner "Check 28: Where can written to and executed from? A few 'common' places: /tmp, /var/tmp, /dev/shm"
find / -writable -type d 2>/dev/null      # world-writeable folders
find / -perm -222 -type d 2>/dev/null     # world-writeable folders
find / -perm -o w -type d 2>/dev/null     # world-writeable folders
find / -perm -o x -type d 2>/dev/null     # world-executable folders
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null   

banner "Check 29: World-writeable & executable folders. Any problem files? Word-writeable, nobody files"
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null # world-writeable files
find /dir -xdev \( -nouser -o -nogroup \) -print  2>/dev/null # Noowner files

banner "Check 30: What development tools/languages are installed/supported?"
find / -name perl* 2>/dev/null
find / -name python* 2>/dev/null
find / -name gcc* 2>/dev/null
find / -name cc 2>/dev/null

banner "Check 40: How can files be uploaded?"
find / -name wget 2>/dev/null
find / -name nc* 2>/dev/null
find / -name netcat* 2>/dev/null
find / -name tftp* 2>/dev/null
find / -name ftp 2>/dev/null
