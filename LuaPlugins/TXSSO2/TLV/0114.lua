--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0114
-------- -------- -------- --------

SSO2::TLV_DHParams_0x114
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors[0x3649] = dissectors[0x3649] or {};

dissectors[0x3649].tlv = dissectors[0x3649].tlv or {};

local proto = require "TXSSO2/Proto";
local fields = require "TXSSO2/Fields";
local fieldsex, fields = unpack( fields );

dissectors[0x3649].tlv[0x0114] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  if ver == 0x0102 then
    off = TreeAddEx( fieldsex, t, buf, off,
      ">wTlvVer W",
      ">bufDHPublicKey",  FormatEx.wxline_string
      );
  end
  if off - oo >= size then
    return;
  end
  TreeAddEx( fieldsex, t, buf, off, ">unsolved", size - ( off - oo ) );
end