--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0017
-------- -------- -------- --------

SSO2::TLV_ClientInfo_0x17
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};


dissectors.tlv[0x0017] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  if ver == 0x0001 then
    off = dissectors.add( t, buf, off,
      ">wTlvVer W",
      ">dwServerTime D",
      ">dwClientWanIP D",
      ">wClientWanPort W",
      ">UnknowBuf", dissectors.format_qqbuf
      );
  end
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end