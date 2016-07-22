local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0014] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off,
    ">wTlvVer W",
    ">xxoo_w"
    );

  dissectors.addex( t, buf, off, size - ( off - oo ) );
end