--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0112
-------- -------- -------- --------

SSO2::TLV_SigIP2_0x112
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0112] = function( buf, pkg, root, t, off, size )
  dissectors.add( t, buf, off, ">*bufSigClientAddr bytes", size );
end