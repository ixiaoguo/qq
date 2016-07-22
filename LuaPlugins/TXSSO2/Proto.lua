--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Proto
-------- -------- -------- --------

返回Proto对象
]=======]
--[=======[
●
  filter      txsso2                  --以此filter单独提取TX SSO2部分
]=======]
local proto = Proto( "TXSSO2", "Tencent SSO Protocol ver.2" );
local proto_port = 8000;              --只做UDP 8000端口解析，其它TCP啥的不管了

local fields = require "TXSSO2/Fields";
local fieldsex, fields = unpack( fields );
proto.fields = fields;

local Packet_PreFix = '\x02';
local Packet_SufFix = '\x03';

local function proto_chk( buf )
  --cPreFix、cSufFix、cMainVer、cSubVer、wCsCmdNo、wCsSenderSeq
  --至少有不小于0x10的数据
  local min_size = 1 + 1 + 1 + 1 + 2 + 2 + 0x10;
  local len = buf:len();
  if len < min_size then
    return false;
  end
  if buf:raw( 0, 1 ) ~= Packet_PreFix then
    return false;
  end
  if buf:raw( len - 1, 1 ) ~= Packet_SufFix then
    return false;
  end
  return true;
end

local aly_lvl = require "TXSSO2/AnalysisLevel";
local CsCmdNo = require "TXSSO2/CsCmdNo";
local dissectors = require "TXSSO2/Dissectors";

local OldDissector = DissectorTable.get("udp.port"):get_dissector( proto_port );
function proto.dissector( buf, pkg, root )
  --合法判定，如果不是TXSSO包，则调用可能存在的旧处理函数
  if not proto_chk( buf ) then
    if not OldDissector then
      return;
    end
    return OldDissector( buf, pkg, root );
  end
  
  pkg.cols.protocol:set( proto.name );

  local cmd = buf( 1 + 1 + 1, 2 ):uint();
  local cmds = CsCmdNo[ cmd ] or "???";
  local ss = string.format( "-%04X-%s-", cmd, cmds );
  --依据目标端口判定输入输出
  if pkg.dst_port == proto_port then
    ss = "●" .. ss;
  else
    ss = "○" .. ss;
  end
  pkg.cols.info:set( ss );

  local t = root:add( proto, buf(), "TXSSO2     : " .. ss );

  local lvl = aly_lvl();
  if lvl == alvlS then
    return;
  end

  --前缀输出
  if lvl == alvlD then
    dissectors.add( t, buf, 0,
      ">cPreFix B"
      );
  end

  local ver = buf( 1, 2 ):uint();

  --对应SSO版本，或选择默认的解析函数组
  local func = dissectors[ ver ] or dissectors.other;
  if func then
    --对应CsCmdNo，或选择默认的解析函数组
    func = func[ cmd ] or func.other;
    if func then
      if pkg.src_port == proto_port then
        func = func.recv;
      else
        func = func.send
      end
    else
      root:add( string.format( "TXSSO2 Dissectors无对应CsCmdNo[%04X]，请添加之", cmd ) );
    end
  else
    root:add( string.format( "TXSSO2 Dissectors无对应SSO版本[%04X]，请添加之", ver ) );
  end

  local data = buf( 1, buf:len() - 2 ):tvb();
  if func then
    local b, err = pcall( func, data, pkg, root, t );
    if not b then
      root:add( "解析TXSSO2失败 : " .. err );
      dissectors.add( t, data, 0, ">unsolved" );
    end
  else
    dissectors.add( t, data, 0, ">unsolved" );
  end

  --后缀输出
  if lvl == alvlD then
    dissectors.add( t, buf, buf:len() - 1,
      ">cSufFix B"
      );
  end
end

DissectorTable.get("udp.port"):add( proto_port, proto );

return proto;