--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 001E
-------- -------- -------- --------

SSO2::TLV_GTKey_TGTGT_0x1e
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x001E] = function( buf, pkg, root, t, off, size )
  local oo = off;
  off = dissectors.add( t, buf, off,
    ">bufTGTGTKey", 0x10
    );
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end