--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0312
-------- -------- -------- --------

SSO2::TLV_Misc_Flag_0x312
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};


dissectors.tlv[0x0312] = function( buf, pkg, root, t, off, size )
  local oo = off;
  off = dissectors.add( t, buf, off,
    ">*const_1 B",
    ">*const_0 D"
    );
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end