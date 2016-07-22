--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Dissectors >>>> Other
-------- -------- -------- --------

Other
]=======]
local dissectors = require "TXSSO2/Dissectors";

local proto = require "TXSSO2/Proto";

local aly_lvl = require "TXSSO2/AnalysisLevel";

local function PCQQCommonSend( buf, pkg, root, t )
  local ver = buf( 0, 2 ):uint();
  local cmd = buf( 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 2, 2 ):uint();

  local lvl = aly_lvl();

  if lvl >= alvlC then
    --输出包头
    local tt = t:add( proto, buf( 0, 0xA ), "bufPacketHeader");
    dissectors.add( tt, buf, 0,
      ">cMainVer B",
      ">cSubVer B",
      ">wCsCmdNo W",
      ">wCsIOSeq W",
      ">dwUin D"
      );
    --输出中段信息
    dissectors.add( t, buf, 0xA,
      ">xxoo_a", 3,
      ">dwClientType D",
      ">dwPubNo D"
      );
  end

  --剩余的数据，尝试解密
  local rest = buf:len() - 0x15;
  local data = buf:raw( 0x15 );
  
  local refkeyname, refkey, ds = dissectors.TeanDecrypt( data );
  if ds == nil or #ds == 0 then
    t:add( proto, buf( 0x15 ), string.format(
      "GeneralCodec_Request [%04X] 解密失败！！！！",
      rest )
      );
    return;
  end
  local info = string.format(
    "GeneralCodec_Request [%04X] >> [%04X]       With Key",
    rest,
    #ds
    );
  local c, s, n = TXSSO2_AnalysisKeyName( refkeyname );
  if c then
    if n == tostring( pkg.number ) then
      info = info .. "    by frame self ↑↑↑";
      n = nil;
    else
      info = info .. ":" .. refkey:sub( 1, 0x10 ):hex2str( true ) .. "       form FrameNum:" .. n;
    end
  else
    info = info .. "[" .. refkeyname .. "]:" .. refkey:sub( 1, 0x10 ):hex2str( true );
    n = refkeyname:match( "^f(%d+)_" );
  end
  local tt = t:add( proto, buf( 0x15 ), info );
  if n then
    dissectors.keyframe( tt, tonumber( n ) );
  end

  data = ByteArray.new( ds, true ):tvb( "Decode" );
  return data, tt;
end

local function PCQQCommonRecv( buf, pkg, root, t )
  local ver = buf( 0, 2 ):uint();
  local cmd = buf( 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 2, 2 ):uint();

  local lvl = aly_lvl();

  if lvl >= alvlC then
    --包头
    local tt = t:add( proto, buf( 0, 0xA ), "bufPacketHeader");
    dissectors.add( tt, buf, 0,
      ">cMainVer B",
      ">cSubVer B",
      ">wCsCmdNo W",
      ">wCsIOSeq W",
      ">dwUin D"
      );
    --中段信息
    dissectors.add( t, buf, 0xA,
      ">xxoo_a", 3
      );
  end

  local rest = buf:len() - 0xD;
  local data = buf:raw( 0xD );
  
  local refkeyname, refkey, ds = dissectors.TeanDecrypt( data );
  if ds == nil or #ds == 0 then
    t:add( proto, buf( 0xD ), string.format(
      "GeneralCodec_Response [%04X] 解密失败！！！！",
      rest )
      );
    return;
  end

  local info = string.format(
    "GeneralCodec_Response [%04X] >> [%04X]       With Key",
    rest,
    #ds
    );
  local c, s, n = TXSSO2_AnalysisKeyName( refkeyname );
  if c then
    if n == tostring( pkg.number ) then
      info = info .. "    by frame self ↑↑↑";
      n = nil;
    else
      info = info .. ":" .. refkey:sub( 1, 0x10 ):hex2str( true ) .. "       form FrameNum:" .. n;
    end
  else
    info = info .. "[" .. refkeyname .. "]:" .. refkey:sub( 1, 0x10 ):hex2str( true );
    n = refkeyname:match( "^f(%d+)_" );
  end
  local tt = t:add( proto, buf( 0xD ), info );
  if n then
    dissectors.keyframe( tt, tonumber( n ) );
  end
  
  local data = ByteArray.new( ds, true ):tvb( "Decode" );
  
  return data, tt;
end

local function PCQQSend( buf, pkg, root, t )
  local data, tt = PCQQCommonSend( buf, pkg, root, t );
  dissectors.add( tt, data, 0, ">unsolved" );
end

local function PCQQRecv( buf, pkg, root, t )
  local data, tt = PCQQCommonRecv( buf, pkg, root, t );
  dissectors.add( tt, data, 0, ">unsolved" );
end

dissectors.other = dissectors.other or {};
dissectors.other.other = dissectors.other.other or {};
dissectors.other.other.commonsend = dissectors.other.other.commonsend or PCQQCommonSend;
dissectors.other.other.commonrecv = dissectors.other.other.commonrecv or PCQQCommonRecv;
dissectors.other.other.send = dissectors.other.other.send or PCQQSend;
dissectors.other.other.recv = dissectors.other.other.recv or PCQQRecv;