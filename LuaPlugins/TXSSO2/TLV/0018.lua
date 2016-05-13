--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0018
-------- -------- -------- --------

SSO2::TLV_Ping_0x18
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0018] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  if ver == 0x0001 then
    off = dissectors.add( t, buf, off,
      ">wTlvVer W",
      ">dwSSOVersion D",
      ">dwServiceId D",
      ">dwClientVer D",
      ">dwUin D"
      );
    local wRedirectCount = buf( off, 2 ):uint();
    off = dissectors.add( t, buf, off, ">wRedirectCount W" );
    for k = 1, wRedirectCount do
      off = dissectors.add( t, buf, off, ">dwRedirectIP D" );
    end
    off = dissectors.add( t, buf, off, ">*NullBuf wxline_bytes" );
  end
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end