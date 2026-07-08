# RedSun
The Red Sun vulnerability repository

Now, normally I would just drop the PoC code and let people figure it out. But I can't for this one, it's way too funny.
When Windows Defender realizes that a malicious file has a cloud tag, for whatever stupid and hilarious reason, the antivirus that's supposed to protect decides that it is a good idea to just rewrite the file it found again to it's original location. The PoC abuses this behaviour to overwrite system files and gain administrative privileges.

I think antimalware products are supposed to remove malicious files not be sure they are there but that's just me.

![BottomText](redsun.jpg)
