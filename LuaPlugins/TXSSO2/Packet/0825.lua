--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Dissectors >>>> 0825
-------- -------- -------- --------

Ping
]=======]

local cmdno = 0x0825;

local dissectors = require "TXSSO2/Dissectors";

local proto = require "TXSSO2/Proto";

local aly_lvl = require "TXSSO2/AnalysisLevel";

local function PCQQSend( buf, pkg, root, t )
  local ver = buf( 0, 2 ):uint();
  local cmd = buf( 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 2, 2 ):uint();

  local key = buf:raw( 0x19, 0x10 );
  TXSSO2_Add2KeyChain( TXSSO2_MakeKeyName( cmd, seq, pkg.number ), key );

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
      ">dwPubNo D",
      ">xxoo_d",
      ">bufCsPrefix", 0x10
      );
  end

  --剩余的数据，尝试解密
  local rest = buf:len() - 0x29;
  local data = buf:raw( 0x29 );
  
  local refkeyname, refkey, ds = dissectors.TeanDecrypt( data );
  if ds == nil or #ds == 0 then
    t:add( proto, buf( 0x29 ), string.format(
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
  local tt = t:add( proto, buf( 0x29 ), info );
  if n then
    dissectors.keyframe( tt, tonumber( n ) );
  end

  data = ByteArray.new( ds, true ):tvb( "Decode" );
  dissectors.dis_tlv( data, pkg, root, tt, 0, data:len() );
end

local function PCQQRecv( buf, pkg, root, t )
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
  
  local off = 0;
  off = dissectors.add( tt, data, off, ">cResult B" );

  dissectors.dis_tlv( data, pkg, root, tt, off, data:len() - off );
end

dissectors.other = dissectors.other or {};
dissectors.other[cmdno] = dissectors.other[cmdno] or {};
dissectors.other[cmdno].send = dissectors.other[cmdno].send or PCQQSend;
dissectors.other[cmdno].recv = dissectors.other[cmdno].recv or PCQQRecv;