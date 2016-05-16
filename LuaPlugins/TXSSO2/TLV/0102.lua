--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0102
-------- -------- -------- --------

SSO2::TLV_Official_0x102
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

local proto = require "TXSSO2/Proto";

--本来想辅助检验Official，可是lua5.2引进的string.pack/unpack好像一直有点问题，故放弃了

dissectors.tlv[0x0102] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then

    local bufOfficialKey = buf:raw( off, 0x10 );
    off = dissectors.add( t, buf, off, ">bufOfficialKey", 0x10 );

    local bufSigPic = FormatEx.wxline_string( buf, off );
    off = dissectors.add( t, buf, off, ">bufSigPic", FormatEx.wxline_bytes );

    local bufOfficial_crc32, size = FormatEx.wxline_string( buf, off );
    local tt = t:add( proto, buf( off, size ), "bufOfficial & crc32" );
    dissectors.add( tt, buf, off + 2,
      ">bufOfficial", 0x10,
      ">crc32 D"
      );
    off = off + size;
  end
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end