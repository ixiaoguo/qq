--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0005
-------- -------- -------- --------

SSO2::TLV_Uin_0x5
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0005] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0002 then
    off = dissectors.add( t, buf, off, ">dwUin D" );
  end
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end