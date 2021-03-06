﻿--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Dissectors >>>> 0836
-------- -------- -------- --------

GetTGTGT
]=======]
local cmdno = 0x0836;

local dissectors = require "TXSSO2/Dissectors";

local proto = require "TXSSO2/Proto";

local keychain = require "TXSSO2/KeyChain";

local aly_lvl = require "TXSSO2/AnalysisLevel";

local function PCQQSend( buf, pkg, root, t )
  local ver = buf( 0, 2 ):uint();
  local cmd = buf( 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 2, 2 ):uint();
  local qq = buf( 1 + 1 + 2 + 2, 4 ):uint();

  TXSSO2_SetPsSaltKey( qq );    --用默认密码做一个KEY加入KeyChain，以便后面的解析

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
      ">*SubVer W",
      ">*ECDH版本 W"
      );
  end

  local off = 0x1D;
  local bufDHPublicKey_size = buf( off, 2 ):uint();

  --local bufDHPublicKey = buf:raw( off + 2, bufDHPublicKey_size );
  --TXSSO2_Add2KeyChain( string.format( "s%04Xf%d_DHPublicKey", seq, pkg.number ), bufDHPublicKey );

  local key = buf:raw( off + 2 + bufDHPublicKey_size + 4, 0x10 );
  TXSSO2_Add2KeyChain( TXSSO2_MakeKeyName( cmd, seq, pkg.number ), key );
  
  if lvl >= alvlC then
    dissectors.add( t, buf, off,
      ">bufDHPublicKey", dissectors.format_qqbuf,
      ">*dwCsCmdCryptKeySize D",
      ">bufCsPrefix", 0x10
      );
  end
  off = off + 2 + bufDHPublicKey_size + 4 + 0x10;

  local rest = buf:len() - off;
  local data = buf:raw( off );
  
  local refkeyname, refkey, ds = dissectors.TeanDecrypt( data );
  if ds == nil or #ds == 0 then
    t:add( proto, buf( off ), string.format(
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
  local tt = t:add( proto, buf( off ), info );
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
    local tt = t:add( proto, buf( 0, 0xA ), "bufPacketHeader");
    dissectors.add( tt, buf, 0,
      ">cMainVer B",
      ">cSubVer B",
      ">wCsCmdNo W",
      ">wCsIOSeq W",
      ">dwUin D"
      );
    dissectors.add( t, buf, 0xA,
      ">xxoo_a", 3
      );
  end

  local rest = buf:len() - 0xD;
  local data = buf:raw( 0xD, rest );
  

  local refkeyname, refkey, ds = dissectors.TeanDecrypt( data );
  if ds == nil or #ds == 0 then
    t:add( proto, buf( 0xD ), string.format(
      "GeneralCodec_Response [%04X] 解密失败！！！！",
      rest )
      );
    return;
  end

  data = ByteArray.new( ds, true ):tvb( "Decode1" );

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
  local tt = t:add( proto, buf( 0xD, rest ), info );
  if n then
    dissectors.keyframe( tt, tonumber( n ) );
  end
  
  --做二次解密尝试，注意，只是尝试，因为要考虑密码错误返回的情况，此时，并不需要二次解密
  local refkeyname, refkey, ds = dissectors.TeanDecrypt( ds );
  if ds and #ds > 0 then
    local info = string.format(
      "GeneralCodec_Response [%04X] >> [%04X]       With Key",
      data:len(),
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
    local ds = ByteArray.new( ds, true ):tvb( "Decode2" );
    tt = tt:add( proto, data( ), info );
    if n then
      dissectors.keyframe( tt, tonumber( n ) );
    end
    data = ds;
  end

  
  local off = 0;
  off = dissectors.add( tt, data, off, ">cResult B" );

  dissectors.dis_tlv( data, pkg, root, tt, off, data:len() - off );
end

dissectors.other = dissectors.other or {};
dissectors.other[cmdno] = dissectors.other[cmdno] or {};
dissectors.other[cmdno].send = dissectors.other[cmdno].send or PCQQSend;
dissectors.other[cmdno].recv = dissectors.other[cmdno].recv or PCQQRecv;