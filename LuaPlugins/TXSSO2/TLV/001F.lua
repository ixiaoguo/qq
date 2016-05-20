--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 001F
-------- -------- -------- --------

TLV_DeviceID
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x001F] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    off = dissectors.add( t, buf, off,
      ">bufDeviceID", size - ( off - oo )
      );
  end
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end