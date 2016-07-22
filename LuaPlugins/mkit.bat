set DstPath=D:\Program Files\Wireshark\LuaPlugins

::mklink /H /J "%DstPath%\TXSSO2"  .\TXSSO2

rd "%DstPath\TXSSO2.luax"

copy .\TXSSO2.lua "%DstPath%\TXSSO2.luax"


::使用方法
::将相应的lua52.dll覆盖Wireshark目录下的lua52.dll。
::在Wireshark目录下新建目录LuaPlugins
::将TXSSO2.lua和TXSSO2文件夹Copy至LuaPlugins目录
::将TXSSO2.lua后缀改为luae。
::have fun