set DstPath=D:\Program Files\Wireshark\LuaPlugins

::mklink /H /J "%DstPath%\TXSSO2"  .\TXSSO2

rd "%DstPath\TXSSO2.luax"

copy .\TXSSO2.lua "%DstPath%\TXSSO2.luax"