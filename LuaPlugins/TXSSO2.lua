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
require "TXSSO2/Packets"
require "TXSSO2/TLV"



--[=======[


-------- -------- 解析函数组 -------- --------
local dissector = {};
dissector.send = {};
dissector.recv = {};

local sends = dissector.send;
local recvs = dissector.recv;

local function fix_dissector( buf, t, off, size, ... )
  local o = TreeAddEx( fieldsex, t, buf, off, ... );
  local on = off + size;
  if o >= on then
    return;
  end
  TreeAddEx( fieldsex, t, buf, o, "unsolved", on - o );
end

function sends.Ping( buf, pkg, root, t, off, size )
  local oldoff = off;
  local tt = t:add( proto, buf(off, 0xA), "bufPacketHeader");
  local off = TreeAddEx( fieldsex, tt, buf, off,
    ">cMainVer B",
    ">cSubVer B",
    ">wCsCmdNo W",
    ">wCsIOSeq W",
    ">dwUin D"
    );
    --[[
  local off = TreeAddEx( fieldsex, t, buf, off,
    ">xxoo_a", 3,
    ">dwClientType D",
    ">dwPubNo D",
    ">xxoo_d"
    );
    ]]
  local key = buf:raw( off, 0x10 );
  local off = TreeAddEx( fieldsex, t, buf, off,
    ">bufCsPrefix", 0x10
    );
  local rest = size - off + oldoff;
  local data = buf:raw( off, rest );
  data = data:tean_dec( key );
  data = ByteArray.new( data, true ):tvb( "Data" );
  t:add( buf(off, rest ),
    string.format("GeneralCodec_Request [%04X] >> [%04X]", rest, data:len() )
    );
end

function dissector.other( buf, pkg, root, t, off, size )
  if aly_lvl ~= alvlD then
    return;
  end
  fix_dissector( buf, t, off, size );
end


]=======]