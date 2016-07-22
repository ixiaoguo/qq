local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x002F] = function( buf, pkg, root, t, off, size )
  off = dissectors.add( t, buf, off,
    ">wTlvVer W",
    ">bufControl", size - 2
    );
end