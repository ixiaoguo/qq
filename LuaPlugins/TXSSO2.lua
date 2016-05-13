--[=======[
-------- -------- -------- --------
       Tencent SSO 2 插件
-------- -------- -------- --------
]=======]
package.path = package.path .. [[;D:\Program Files\Wireshark\LuaPlugins\?.lua;]];
--以下是一些需要预加载的模块
require "TXSSO2/Fields";
require "TXSSO2/Proto";
require "TXSSO2/Dissectors";
require "TXSSO2/Packets";
require "TXSSO2/TLV";