--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 030F
-------- -------- -------- --------

SSO2::TLV_ComputerName_0x30f
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};


dissectors.tlv[0x030F] = function( buf, pkg, root, t, off, size )
  local oo = off;
  off = dissectors.add( t, buf, off,
    ">ComputerName", FormatEx.wxline_string
    );
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end