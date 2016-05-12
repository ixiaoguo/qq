--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Packets
-------- -------- -------- --------

]=======]

local wp = Dir.global_config_path() .. [[LuaPlugins\TXSSO2\Packet\]];

for filename in Dir.open( wp, "lua" ) do
  require( "TXSSO2/Packet/" .. filename:gsub( "%.lua$", "" ):gsub( "%\\", "/" ) );
end
