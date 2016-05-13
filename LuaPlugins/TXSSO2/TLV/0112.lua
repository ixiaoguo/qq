--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0112
-------- -------- -------- --------

SSO2::TLV_SigIP2_0x112
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors[0x3649] = dissectors[0x3649] or {};

dissectors[0x3649].tlv = dissectors[0x3649].tlv or {};

local proto = require "TXSSO2/Proto";
local fields = require "TXSSO2/Fields";
local fieldsex, fields = unpack( fields );

dissectors[0x3649].tlv[0x0112] = function( buf, pkg, root, t, off, size )
  TreeAddEx( fieldsex, t, buf, off, ">*bufSigClientAddr bytes", size );
end