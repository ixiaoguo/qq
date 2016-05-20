--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0108
-------- -------- -------- --------

SSO2::TLV_AccountBasicInfo_0x108
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

local proto = require "TXSSO2/Proto";

dissectors.tlv[0x0108] = function( buf, pkg, root, t, off, size )
  local oo = off;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    local oo = off;
    local ss, size = FormatEx.wxline_string( buf, off );
    local tt = t:add( proto, buf( off, size ),
      string.format( "bufAccountBasicInfo    帐户基本信息   (%04X)", #ss )
      );
    do
      local oo = off;
      local sss, size = FormatEx.wxline_string( buf, off + 2 );
      local ttt = tt:add( proto, buf( off + 2, size ),
        string.format( "bufInAccountValue   (%04X)", #sss )
        );
      
      off = dissectors.add( ttt, buf, off + 2 + 2,
        ">wSSO_Account_wFaceIndex W",
        ">strSSO_Account_strNickName", FormatEx.bxline_string,
        ">cSSO_Account_cGender B",
        ">dwSSO_Account_dwUinFlag D",
        ">cSSO_Account_cAge B"
        );
      off = dissectors.addex( tt, buf, off, size - ( off - oo ) );
    end
    off = dissectors.add( tt, buf, off,
      ">bufSTOther", dissectors.format_qqbuf
      );
    off = dissectors.addex( tt, buf, off, size - ( off - oo ) );
  end
  dissectors.addex( t, buf, off, size - ( off - oo ) );
end