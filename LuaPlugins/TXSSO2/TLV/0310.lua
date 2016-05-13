--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0310
-------- -------- -------- --------

SSO2::TLV_ServerAddress_0x310
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors[0x3649] = dissectors[0x3649] or {};

dissectors[0x3649].tlv = dissectors[0x3649].tlv or {};

local proto = require "TXSSO2/Proto";
local fields = require "TXSSO2/Fields";
local fieldsex, fields = unpack( fields );

dissectors[0x3649].tlv[0x0310] = function( buf, pkg, root, t, off, size )
  local oo = off;
  off = TreeAddEx( fieldsex, t, buf, off, ">dwServerIP D" );
  if off - oo >= size then
    return;
  end
  TreeAddEx( fieldsex, t, buf, off, ">unsolved", size - ( off - oo ) );
end