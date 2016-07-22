local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x010D] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off,
    ">wTlvVer W",
    ">bufSigLastLoginInfo", dissectors.format_qqbuf
    );

  dissectors.addex( t, buf, off, size - ( off - oo ) );
end