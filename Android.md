
# NOX

Connect to Windows Nox Emulator from kali

```
ssh ENG.AHMED\ GAMAL@192.168.1.8 -L 62001:127.0.0.1:62001
```

# ADB

Connect to Emulator with adb

```
adb connect 127.0.01:62001
```

Check connected devices

```
adb devices
```

to copy file to the emulator

```
adb push filename /path/
```

to install app

```
adb -d install package_name.apk
```

To know which file the screen be executed.

```
adb shell dumpsys window | grep 'mCurrentFocus'
```

To know process id

```
adb shell pidof -s *psname
```

To monitor if there's sensitive data exposed.

```
adb logcat --pid=$(adb shell pidof -s package_name)
```

Do actions from  adb and see the response from the application

```
adb shell am start -a android.intent.action.VIEW "http://example.com" 
```

bypass register by using extras

```
adb shell am start -a package_name.VIEW_CREDS2 --ez check_pin false
```

# reflutter

to bypass ssl pinning in flutter apps

```
// from sudo
python3 /usr/local/bin/reflutter app.apk
```
then sign the app with uber-apk-signer

```
java -jar uber-apk-signer-1.3.0.jar --apk release.RE.apk --out app2_signed
```
then change file permission

```
chmod 755 app2_signed
```
# apktool

to decompile an apk

```
apktool d allsafe.apk
```

to build app

```
apktool b indeed/ -o indeed_patched.apk
```

# apkleaks

to search for secrets, endpoints and urls

```
apkleaks -f app.apk -o results.txt
```

# MobSF

to run mobsf, then drag and drop the apk

```
./run.sh 0.0.0.0:8000
```

# Objection

```
/usr/local/bin/objection -g package_name explore
```
For Android

https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting/frida-tutorial/objection-tutorial

For iOS

https://cheatography.com/hnd/cheat-sheets/objection-ios/
https://www.virtuesecurity.com/kb/ios-frida-objection-pentesting-cheat-sheet/

# Frida

Run frida-server from adb

```
adb shell
su
cd data/local/tmp
./frida-server4
```

to list running apps

```
frida-ps -Ua
```

to list installed apps

```
frida-ps -Uai
```

to spawn application with frida

```
frida -U -f infosecadventures.allsafe
```

to execute file with frida

```
frida -U -l hook.js -f infosecadventures.allsafe 
```


# Medusa

```
python3 medusa.py

showall

use module_name

run -f infosecadventures.allsafe
```


# Hardcoded Credentials

Check for

/data/data/package_name/shared_prefs

/data/data/package_name/databases

/data/data/package_name/temp_file

/sdcard

remote-db_link on res-values-strings.xml

# Broadcast Receivers

If exported=true

```
adb shell am broadcast -a infosecadventures.allsafe.action.PROCESS_NOTE --es server "10.10.10.10" --es note 'Hello' --es notification_message 'AndroidPT' -n infosecadventures.allsafe/.challenges.NoteReceiver
```

# Content Provider

if exported=true

```
adb shell content query --uri content://jakhar.aseem.diva.provider.notesprovider/notes
```
