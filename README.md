在大佬的基础上改成了 listen 模式

大佬项目：https://github.com/Humenger/Riru-FridaInstaller

使用方法：

```
marlin:/data/local/tmp # echo "com.jussi.sslpinning" > app.list
adb forward tcp:27042 tcp:26000
frida -R gadget
objection -Ng gadget explore
```