--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 000C
-------- -------- -------- --------

SSO2::TLV_PingRedirect_0xC
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x000C] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    off = dissectors.add( t, buf, off,
      ">xxoo_w",
      ">xxoo_d",
      ">xxoo_d",
      ">xxoo_w"
      );
  elseif ver == 0x0002 then
    off = dissectors.add( t, buf, off,
      ">xxoo_w",
      ">dwIDC D",
      ">dwISP D",
      ">dwRedirectIP D",
      ">wRedirectPort W",
      ">xxoo_d"
      );
  end

  dissectors.addex( t, buf, off, size - ( off - oo ) );
end