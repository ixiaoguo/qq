--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0309
-------- -------- -------- --------

SSO2::TLV_Ping_Strategy_0x309
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0309] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  if ver == 0x0001 then
    off = dissectors.add( t, buf, off,
      ">wTlvVer W",
      ">dwServerIP D"
      );
    local cRedirectCount = buf( off, 1 ):uint();
    off = dissectors.add( t, buf, off, ">cRedirectCount B" );
    for k = 1, cRedirectCount do
      off = dissectors.add( t, buf, off, ">dwRedirectIP D" );
    end
    off = dissectors.add( t, buf, off, ">cPingType B" );
  end
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end