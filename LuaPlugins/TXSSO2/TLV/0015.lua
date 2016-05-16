--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0015
-------- -------- -------- --------

SSO2::TLV_ComputerGuid_0x15
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0015] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    --1.bufComputerID
    --2.bufComputerIDEx
    while off - oo < size do
      off = dissectors.add( t, buf, off,
        ">*机器码序号 B",
        ">*crc32 D",
        ">bufComputerID", FormatEx.wxline_bytes
        );
    end
  end

  dissectors.addex( t, buf, off, size - ( off - oo ) );
end