--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0105
-------- -------- -------- --------

TLV_m_vec0x12c
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0105] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    off = dissectors.add( t, buf, off, ">xxoo_b" );
    local count = buf( off, 1 ):uint();
    off = dissectors.add( t, buf, off, ">*数据个数 B" );
    for k = 1, count do
      off = dissectors.add( t, buf, off,
        ">*buf" .. k .. " string", FormatEx.wxline_bytes
        );
    end
  end
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end