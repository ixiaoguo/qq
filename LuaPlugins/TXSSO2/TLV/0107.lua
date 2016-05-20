--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0107
-------- -------- -------- --------

SSO2::TLV_TicketInfo_0x107
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

local proto = require "TXSSO2/Proto";

dissectors.tlv[0x0107] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    local oo = off;
    local bufTickStatus, size = FormatEx.wxline_string( buf, off );
    local tt = t:add( proto, buf( off, size ),
      string.format( "bufTickStatus  凭据状态   (%04X)", #bufTickStatus )
      );
    off = dissectors.add( tt, buf, off + 2,
      ">dwTGTServiceID D",
      ">dwTGTPriority D",
      ">dwTGTRefreshInterval D",
      ">dwTGTValidInterval D",
      ">dwTGTTryInterval D",
      ">wTGTTryCount W"
      );
    off = dissectors.addex( tt, buf, off, size - ( off - oo ) );

    local key = buf:raw( off, 0x10 );
    TXSSO2_Add2KeyChain( "f" .. pkg.number .. "_TGT_GTKey", key );
    off = dissectors.add( t, buf, off,
      ">bufTGT_GTKey", 0x10,
      ">bufTGT", dissectors.format_qqbuf
      );
      
    local key = buf:raw( off, 0x10 );
    TXSSO2_Add2KeyChain( "f" .. pkg.number .. "_GTKey_ST", key );
    off = dissectors.add( t, buf, off,
      ">buf16bytesGTKey_ST", 0x10,
      ">bufServiceTicket", dissectors.format_qqbuf
      );

    local oo = off;
    local bufSTHttp, size = FormatEx.wxline_string( buf, off );
    local tt = t:add( proto, buf( off, size ),
      string.format( "bufSTHttp  HTTP凭据   (%04X)", #bufSTHttp )
      );
    
    local key = buf:raw( off + 2 + 1, 0x10 );
    TXSSO2_Add2KeyChain( "f" .. pkg.number .. "_GTKey_STHttp", key );
    off = dissectors.add( tt, buf, off + 2,
      ">bAllowPtlogin B",
      ">buf16bytesGTKey_STHttp", 0x10,
      ">bufServiceTicketHttp", dissectors.format_qqbuf
      );
    off = dissectors.addex( tt, buf, off, size - ( off - oo ) );

      
    local key = buf:raw( off, 0x10 );
    TXSSO2_Add2KeyChain( "f" .. pkg.number .. "_GTKey_TGTPwd", key );
    off = dissectors.add( t, buf, off,
      ">bufGTKey_TGTPwd", 0x10
      );
  end
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end