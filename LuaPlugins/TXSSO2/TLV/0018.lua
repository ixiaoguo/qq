--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0018
-------- -------- -------- --------

SSO2::TLV_Ping_0x18
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors[0x3649] = dissectors[0x3649] or {};

dissectors[0x3649].tlv = dissectors[0x3649].tlv or {};

local proto = require "TXSSO2/Proto";
local fields = require "TXSSO2/Fields";
local fieldsex, fields = unpack( fields );

dissectors[0x3649].tlv[0x0018] = function( buf, pkg, root, t, off, size )
  local oo = off;
  off = TreeAddEx( fieldsex, t, buf, off,
    ">wTlvVer W",
    ">dwSSOVersion D",
    ">dwServiceId D",
    ">dwClientVer D",
    ">dwUin D"
    );
  local wRedirectCount = buf( off, 2 ):uint();
  off = TreeAddEx( fieldsex, t, buf, off, ">wRedirectCount W" );
  for k = 1, wRedirectCount do
    off = TreeAddEx( fieldsex, t, buf, off, ">dwRedirectIP D" );
  end
  off = TreeAddEx( fieldsex, t, buf, off, ">*NullBuf wxline_bytes" );
  if off - oo >= size then
    return;
  end
  TreeAddEx( fieldsex, t, buf, off, ">unsloved", size - ( off - oo ) );
end