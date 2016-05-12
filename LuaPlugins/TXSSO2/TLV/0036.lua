--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0036
-------- -------- -------- --------

SSO2::TLV_LoginReason_0x36
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors[0x3649] = dissectors[0x3649] or {};

dissectors[0x3649].tlv = dissectors[0x3649].tlv or {};

local proto = require "TXSSO2/Proto";
local fields = require "TXSSO2/Fields";
local fieldsex, fields = unpack( fields );

dissectors[0x3649].tlv[0x0036] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = TreeAddEx( fieldsex, t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    off = TreeAddEx( fieldsex, t, buf, off,
      ">*const_1 W",
      ">*const_0 D",
      ">*const_0 W"
      );
  elseif ver == 0x0002 then
    off = TreeAddEx( fieldsex, t, buf, off,
      ">*const_1 W",
      ">*const_0 D",
      ">*const_0 W",
      ">*const_0 W",
      ">*const_0 D",
      ">*const_0 B",
      ">*const_0 B"
      );
  else
    off = TreeAddEx( fieldsex, t, buf, off,
      ">*const_1 W",
      ">*const_0 D",
      ">*const_0 W",
      ">*const_0 W",
      ">*const_0 D",
      ">*const_0 B",
      ">*const_0 B"
      );
  end

  if off - oo >= size then
    return;
  end
  TreeAddEx( fieldsex, t, buf, off, ">unsloved", size - ( off - oo ) );
end