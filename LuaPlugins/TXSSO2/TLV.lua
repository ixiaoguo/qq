--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV
-------- -------- -------- --------
]=======]

local wp = Dir.global_config_path() .. [[LuaPlugins\TXSSO2\TLV\]];

for filename in Dir.open( wp, "lua" ) do
  require( "TXSSO2/TLV/" .. filename:gsub( "%.lua$", "" ):gsub( "%\\", "/" ) );
end
