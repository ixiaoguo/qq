--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0309
-------- -------- -------- --------

SSO2::TLV_Ping_Strategy_0x309
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors[0x3649] = dissectors[0x3649] or {};

dissectors[0x3649].tlv = dissectors[0x3649].tlv or {};

local proto = require "TXSSO2/Proto";
local fields = require "TXSSO2/Fields";
local fieldsex, fields = unpack( fields );

dissectors[0x3649].tlv[0x0309] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  if ver == 0x0001 then
    off = TreeAddEx( fieldsex, t, buf, off,
      ">wTlvVer W",
      ">dwServerIP D"
      );
    local cRedirectCount = buf( off, 1 ):uint();
    off = TreeAddEx( fieldsex, t, buf, off, ">cRedirectCount B" );
    for k = 1, cRedirectCount do
      off = TreeAddEx( fieldsex, t, buf, off, ">dwRedirectIP D" );
    end
    off = TreeAddEx( fieldsex, t, buf, off, ">cPingType B" );
  end
  if off - oo >= size then
    return;
  end
  TreeAddEx( fieldsex, t, buf, off, ">unsolved", size - ( off - oo ) );
end