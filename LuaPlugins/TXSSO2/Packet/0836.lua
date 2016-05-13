--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Dissectors >>>> 0836
-------- -------- -------- --------

GetTGTGT
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors[0x3649] = dissectors[0x3649] or {};

dissectors[0x3649][0x0836] = dissectors[0x3649][0x0836] or {};

local proto = require "TXSSO2/Proto";

local keychain = require "TXSSO2/KeyChain";

local aly_lvl = require "TXSSO2/AnalysisLevel";

dissectors[0x3649][0x0836].send = function( buf, pkg, root, t )
  local ver = buf( 1, 2 ):uint();
  local cmd = buf( 1 + 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 1 + 2, 2 ):uint();
  local qq = buf( 1 + 1 + 1 + 2 + 2, 4 ):uint();

  TXSSO2_SetPsSaltKey( qq );


  local lvl = aly_lvl();

  if lvl >= alvlC then
    local tt = t:add( proto, buf( 1, 0xA ), "bufPacketHeader");
    dissectors.add( tt, buf, 1,
      ">cMainVer B",
      ">cSubVer B",
      ">wCsCmdNo W",
      ">wCsIOSeq W",
      ">dwUin D"
      );
    dissectors.add( t, buf, 0xB,
      ">xxoo_a", 3,
      ">dwClientType D",
      ">dwPubNo D",
      ">xxoo_d",
      ">*SubVer W",
      ">*ECDH版本 W"
      );
  end

  local off = 0x1E;
  local bufDHPublicKey_size = buf( off, 2 ):uint();

  --local bufDHPublicKey = buf:raw( off + 2, bufDHPublicKey_size );
  --TXSSO2_Add2KeyChain( string.format( "s%04Xf%d_DHPublicKey", seq, pkg.number ), bufDHPublicKey );

  local key = buf:raw( off + 2 + bufDHPublicKey_size + 4, 0x10 );
  TXSSO2_Add2KeyChain( TXSSO2_MakeKeyName( cmd, seq, pkg.number ), key );
  
  if lvl >= alvlC then
    dissectors.add( t, buf, off,
      ">bufDHPublicKey", FormatEx.wxline_string,
      ">*dwCsCmdCryptKeySize D",
      ">bufCsPrefix", 0x10
      );
  end
  off = off + 2 + bufDHPublicKey_size + 4 + 0x10;

  local rest = buf:len() - 1 - off;
  local data = buf:raw( off, rest );
  
  local refkeyname,refkey, ds = dissectors.TeanDecrypt( data );
  if ds == nil or #ds == 0 then
    t:add( proto, buf( off, rest ), string.format(
      "GeneralCodec_Request [%04X] 解密失败！！！！",
      rest )
      );
    return;
  end
  data = ByteArray.new( ds, true ):tvb( "Decode" );

  local info = string.format(
    "GeneralCodec_Request [%04X] >> [%04X]       With Key",
    rest,
    data:len()
    );
  local c, s, n = TXSSO2_AnalysisKeyName( refkeyname );
  if c then
    if n == tostring( pkg.number ) then
      info = info .. "    by frame self ↑↑↑";
    else
      info = info .. ":" .. refkey:sub( 1, 0x10 ):hex2str( true ) .. "       form FrameNum:" .. n;
    end
  else
    info = info .. "[" .. refkeyname .. "]:" .. refkey:sub( 1, 0x10 ):hex2str( true );
  end
  local tt = t:add( proto, buf( off, rest ), info );
  
  dissectors.dis_tlv( data, pkg, root, tt, 0, data:len() );
end

dissectors[0x3649][0x0836].recv = function( buf, pkg, root, t )
  local ver = buf( 1, 2 ):uint();
  local cmd = buf( 1 + 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 1 + 2, 2 ):uint();

  local lvl = aly_lvl();

  if lvl >= alvlC then
    local tt = t:add( proto, buf( 1, 0xA ), "bufPacketHeader");
    dissectors.add( tt, buf, 1,
      ">cMainVer B",
      ">cSubVer B",
      ">wCsCmdNo W",
      ">wCsIOSeq W",
      ">dwUin D"
      );
    dissectors.add( t, buf, 0xB,
      ">xxoo_a", 3
      );
  end

  local rest = buf:len() - 1 - 0xE;
  local data = buf:raw( 0xE, rest );
  

  local refkeyname,refkey, ds = dissectors.TeanDecrypt( data );
  if ds == nil or #ds == 0 then
    t:add( proto, buf( 0xE, rest ), string.format(
      "GeneralCodec_Response [%04X] 解密失败！！！！",
      rest )
      );
    return;
  end
  data = ByteArray.new( ds, true ):tvb( "Decode" );

  local info = string.format(
    "GeneralCodec_Response [%04X] >> [%04X]       With Key",
    rest,
    data:len()
    );
  do return; end
end