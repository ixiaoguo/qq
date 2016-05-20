--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0007
-------- -------- -------- --------

TLV_TGT
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0007] = function( buf, pkg, root, t, off, size )
  dissectors.add( t, buf, off,
      ">TGT", size
      );
end