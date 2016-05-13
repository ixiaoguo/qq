--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0006
-------- -------- -------- --------

SSO2::TLV_TGTGT_0x6
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

local proto = require "TXSSO2/Proto";

dissectors.tlv[0x0006] = function( buf, pkg, root, t, off, size )
  local data = buf:raw( off, size );

  local refkeyname,refkey, ds = dissectors.TeanDecrypt( data );
  if ds == nil or #ds == 0 then
    t:add( buf( off, size ), "TGTGT解密失败！！！！" );
    return;
  end
  
  local info = string.format(
    "TGTGT [%04X] >> [%04X]       With Key",
    size,
    ds:len()
    );
  info = info .. "[" .. refkeyname .. "]:" .. refkey:sub( 1, 0x10 ):hex2str( true );
  local tt = t:add( proto, buf( off, size ), info );

  buf = ByteArray.new( ds, true ):tvb( "TGTGT" );

  local ver = buf( 4, 2 ):uint();
  local off = 0;
  
  if ver == 0x0002 then
    off = dissectors.add( tt, buf, off,
      ">*dwRand随机值 D",
      ">wTlvVer W",
      ">dwUin D",
      ">dwSSOVersion D",
      ">dwServiceId D",
      ">dwClientVer D",
      ">*const_0 W",
      ">bRememberPwdLogin B",
      ">bufPsMD5", 0x10,
      ">dwServerTime D",
      ">*const_0 bytes", 0xD,
      ">dwClientWanIP D",
      ">dwISP D",
      ">dwIDC D",
      ">bufComputerID", FormatEx.wxline_string
      );
    local key = buf:raw( off, 0x10 );
    TXSSO2_Add2KeyChain( string.format( "f%d_TGTGTKey", pkg.number ), key );
    off = dissectors.add( tt, buf, off, ">bufTGTGTKey", 0x10 );
  end
  
  dissectors.addex( tt, buf, off, buf:len() - off );
end