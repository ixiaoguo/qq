--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 000C
-------- -------- -------- --------

SSO2::TLV_PingRedirect_0xC
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors[0x3649] = dissectors[0x3649] or {};

dissectors[0x3649].tlv = dissectors[0x3649].tlv or {};

local proto = require "TXSSO2/Proto";
local fields = require "TXSSO2/Fields";
local fieldsex, fields = unpack( fields );

dissectors[0x3649].tlv[0x000C] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = TreeAddEx( fieldsex, t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    off = TreeAddEx( fieldsex, t, buf, off,
      ">xxoo_w",
      ">xxoo_d",
      ">xxoo_d",
      ">xxoo_w"
      );
  elseif ver == 0x0002 then
    off = TreeAddEx( fieldsex, t, buf, off,
      ">xxoo_w",
      ">dwIDC D",
      ">dwISP D",
      ">dwRedirectIP D",
      ">wRedirectPort W",
      ">xxoo_d"
      );
  end

  if off - oo >= size then
    return;
  end
  TreeAddEx( fieldsex, t, buf, off, ">unsolved", size - ( off - oo ) );
end