local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x010E] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    local sss = buf( off, 2 ):uint();
    local tt = t:add( proto, buf( off, 2 + sss ), string.format( "info (%04X)", sss ) );
    off = dissectors.add( tt, buf, off + 2,
      ">dwUinLevel D",
      ">dwUinLevelEx D",
      ">buf24byteSignature", dissectors.format_qqbuf,
      ">buf32byteValueAddedSignature", dissectors.format_qqbuf,
      ">buf12byteUserBitmap", dissectors.format_qqbuf
      );
  end
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end