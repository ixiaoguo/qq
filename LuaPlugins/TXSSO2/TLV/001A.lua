--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 001A
-------- -------- -------- --------

SSO2::TLV_GTKeyTGTGTCryptedData_0x1a
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

local proto = require "TXSSO2/Proto";

dissectors.tlv[0x001A] = function( buf, pkg, root, t, off, size )
  local data = buf:raw( off, size );

  local refkeyname,refkey, ds = dissectors.TeanDecrypt( data );
  if ds == nil or #ds == 0 then
    t:add( proto, buf( off, size ), "GTKeyTGTGTCryptedData解密失败！！！！" );
    return;
  end
  
  local info = string.format(
    "GTKeyTGTGTCryptedData [%04X] >> [%04X]       With Key",
    size,
    ds:len()
    );
  info = info .. "[" .. refkeyname .. "]:" .. refkey:sub( 1, 0x10 ):hex2str( true );
  local tt = t:add( proto, buf( off, size ), info );

  buf = ByteArray.new( ds, true ):tvb( "GTKeyTGTGTCryptedData" );

  dissectors.dis_tlv( buf, pkg, root, tt, 0, buf:len() );
end