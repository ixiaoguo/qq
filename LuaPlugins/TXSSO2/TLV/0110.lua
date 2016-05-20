--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0110
-------- -------- -------- --------

SSO2::TLV_SigPic_0x110
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0110] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    off = dissectors.add( t, buf, off,
      ">bufSigPic", dissectors.format_qqbuf
      );
  end
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end