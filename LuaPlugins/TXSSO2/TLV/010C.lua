local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

local proto = require "TXSSO2/Proto";

dissectors.tlv[0x010C] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    local key = buf:raw( off, 0x10 );
    TXSSO2_Add2KeyChain( string.format( "f%d_16byteSessionKey", pkg.number ), key );
    off = dissectors.add( t, buf, off,
      ">buf16byteSessionKey", 0x10,
      ">dwUin D",
      ">dwClientIP D",
      ">wClientPort W",
      ">dwServerTime D", dissectors.format_time,
      ">xxoo_d",
      ">cPassSeqID B",
      ">dwConnIP D",
      ">dwReLoginConnIP D",
      ">dwReLoginCtrlFlag D",
      ">bufComputerIDSig", dissectors.format_qqbuf,
      ">xxoo_s", FormatEx.bxline_bytes
      );
    local ss, size = FormatEx.wxline_string( buf, off );
    local tt = t:add( proto, buf( off, 2 + size ), "Unknow" );
    off = dissectors.add( tt, buf, off + 2,
      ">xxoo_b",
      ">dwConnIP D"
      );
  end
  
  dissectors.addex( t, buf, off, oo - off );
end