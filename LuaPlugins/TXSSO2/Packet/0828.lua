--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Dissectors >>>> 0825
-------- -------- -------- --------

Ping
]=======]
local cmdno = 0x0828;

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
    local tt = t:add( proto, buf( 0, 0xA ), "bufPacketHeader");
    dissectors.add( tt, buf, 0,
      ">cMainVer B",
      ">cSubVer B",
      ">wCsCmdNo W",
      ">wCsIOSeq W",
      ">dwUin D"
      );
    dissectors.add( t, buf, 0xA,
      ">xxoo_a", 3,
      ">dwClientType D",
      ">dwPubNo D",
      ">xxoo_d",
      ">bufSession", FormatEx.wxline_bytes
      );
  end

  local bufSessionSize = buf( 0x19, 2 ):uint();
  local offs = 0x19 + 2 + bufSessionSize;

  local rest = buf:len() - offs;
  local data = buf:raw( offs, rest );
  
  local refkeyname, refkey, ds = dissectors.TeanDecrypt( data );
  if ds == nil or #ds == 0 then
    t:add( proto, buf( offs, rest ), string.format(
      "GeneralCodec_Request [%04X] 解密失败！！！！",
      rest )
      );
    return;
  end

  local info = string.format(
    "GeneralCodec_Request [%04X] >> [%04X]       With Key",
    rest,
    data:len()
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
  local tt = t:add( proto, buf( offs, rest ), info );
  if n then
    dissectors.keyframe( tt, tonumber( n ) );
  end

  data = ByteArray.new( ds, true ):tvb( "Decode" );
  dissectors.dis_tlv( data, pkg, root, tt, 0, data:len() );
end

require "TXSSO2/Packet/0825";

local PCQQRecv = dissectors.other[0x0825].recv;

dissectors.other = dissectors.other or {};
dissectors.other[cmdno] = dissectors.other[cmdno] or {};
dissectors.other[cmdno].send = dissectors.other[cmdno].send or PCQQSend;
dissectors.other[cmdno].recv = dissectors.other[cmdno].recv or PCQQRecv;