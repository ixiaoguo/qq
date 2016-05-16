--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0005
-------- -------- -------- --------

SSO2::TLV_GUID_Ex_0x313
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

local GuidName =
  {
  [2] = "bufMacGuid",
  [4] = "bufComputerIDEx",
  [6] = "bufMachineInfoGuid",
  }

dissectors.tlv[0x0313] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 1 ):uint();
  off = dissectors.add( t, buf, off, ">*cSubVer B" );
  if ver == 0x01 then
    local c = buf( off, 1 ):uint();
    off = dissectors.add( t, buf, off, ">*GUID个数 B" );
    for k = 1, c do
      local n = buf( off, 1 ):uint();
      off = dissectors.add( t, buf, off, ">*GUID索引号 B" );
      local name = GuidName[ n ] or ( "Unknow" .. n );
      off = dissectors.add( t, buf, off,
        ">*" .. name .. " wxline_bytes",
        ">*建立耗时 D"
        );
    end
  end
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end