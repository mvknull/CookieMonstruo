# CookieMonstruo
Post-exploitation tool for cookie stealing and session hijacking.
The tool can be used to dump the cookie database of a compromised Windows machine. By defining specific targets (facebook, gmail) an active session can be detected. Additionally other functionality like waiting until the user logs in and also removing the stolen cookies from the database is supported. 

##Usage Example


Dump all cookies from Chrome:

```Invoke-CookieMonstruo -Browser chrome```

Dump the Facebook session cookies from Chrome:

```Invoke-CookieMonstruo -Browser chrome -Target facebook```

If the user is not logged onto the target application, will run a loop and wait until it detects the session cookie belonging to it:

```Invoke-CookieMonstruo -Browser chrome -Target facebook -WaitSteal```
 
 The target cookies will be deleted from the victim's cookie database:

```Invoke-CookieMonstruo -Browser chrome -Target facebook -RemoveCookie```
 
 
##Supported target applications
 
* Facebook
* Gmail

##Supported browsers

* Chrome
* Firefox
