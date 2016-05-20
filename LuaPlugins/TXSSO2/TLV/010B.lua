--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 010B
-------- -------- -------- --------

TLV_QDLoginFlag
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

local proto = require "TXSSO2/Proto";

dissectors.tlv[0x010B] = function( buf, pkg, root, t, off, size )

  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0002 then
    off = dissectors.add( t, buf, off,
      ">bufQQMd5", 0x10,
      ">QdFlag B",
      ">*const_10 B",
      ">*const_0 D",
      ">*const_2 D"
      );
    local QdData, size = FormatEx.wxline_string( buf, off );
    local tt = t:add( proto, buf( off, size ), "QdData" );
    --dissectors.dis_tlv( buf, pkg, root, tt, 0, buf:len() );
    off = off + size;
    off = dissectors.add( t, buf, off,
      ">*bufUnknow string", FormatEx.wxline_bytes,
      ">*bufUnknow string", FormatEx.wxline_bytes
      );
  end
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end