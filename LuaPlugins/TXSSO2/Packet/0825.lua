--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Dissectors >>>> 0825
-------- -------- -------- --------

解析函数总表



返回表
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors[0x3649] = dissectors[0x3649] or {};

dissectors[0x3649][0x0825] = dissectors[0x3649][0x0825] or {};

local proto = require "TXSSO2/Proto";
local fields = require "TXSSO2/Fields";
local fieldsex, fields = unpack( fields );

local keychain = require "TXSSO2/KeyChain";
local tagname = require "TXSSO2/TagName";

local aly_lvl = require "TXSSO2/AnalysisLevel";

dissectors[0x3649][0x0825].send = function( buf, pkg, root, t )
  local ver = buf( 1, 2 ):uint();
  local cmd = buf( 1 + 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 1 + 2, 2 ):uint();
  local tt = t:add( proto, buf( 1, 0xA ), "bufPacketHeader");
  
  local key = buf:raw( 0x1A, 0x10 );
  TXSSO2_Add2KeyChain( TXSSO2_MakeKeyName( cmd, seq, pkg.number ), key );

  local lvl = aly_lvl();

  if lvl >= alvlC then
    TreeAddEx( fieldsex, tt, buf, 1,
      ">cMainVer B",
      ">cSubVer B",
      ">wCsCmdNo W",
      ">wCsIOSeq W",
      ">dwUin D",
      ">xxoo_a", 3,
      ">dwClientType D",
      ">dwPubNo D",
      ">xxoo_d",
      ">bufCsPrefix", 0x10
      );
  end

  local rest = buf:len() - 1 - 0x2A;
  local data = buf:raw( 0x2A, rest );
  
  local refkeyname,refkey, ds;
  for k, v in pairs( keychain ) do
    ds = TeanDecrypt( data, v );
    if ds ~= nil and #ds > 0 then
      refkeyname = k;
      refkey = v;
      break;
    end
  end
  if ds == nil or #ds == 0 then
    t:add( buf( 0x2A, rest ), string.format(
      "GeneralCodec_Request [%04X] 解密失败",
      rest )
      );
    return;
  end
  data = ByteArray.new( ds, true ):tvb( "Decode" );

  local info = string.format(
    "GeneralCodec_Request [%04X] >> [%04X]       With Key",
    rest,
    data:len()
    );
  local c, s, n = TXSSO2_AnalysisKeyName( refkeyname );
  if c then
    if n == tostring( pkg.number ) then
      info = info .. "    by frame self ↑↑↑";
    else
      info = info .. ":" .. refkey:sub( 1, 0x10 ):hex2str( true ) .. "       form FrameNum:" .. n;
    end
  else
    info = info .. "[" .. refkeyname .. "]:" .. refkey:sub( 1, 0x10 ):hex2str( true );
  end
  local tt = t:add( buf( 0x2A, rest ), info );

  local off = 0;
  while off < data:len() do
    local tag = data( off + 0, 2 ):uint();
    local len = data( off + 2, 2 ):uint();
    local tags = tagname[ tag ] or "UnknownTag";
    local info = string.format( "%04X_%-20s     lenght : %04X", tag, tags, len );

    local ttt = tt:add( data( off, 2 + 2 + len ), info );
    if lvl >= alvlC then
      local func = dissectors[ ver ];
      if func then
        func = func.tlv;
        if func then
          func = func[ tag ];
          if func then
            pcall( func, data, pkg, root, ttt, off + 2 + 2, len );
          else
            root:add( "TXSSO Dissectors无对应TLV" .. string.format( "%04X", tag ) );
          end
        else
          root:add( "TXSSO Dissectors无TLV" );
        end
      else
        root:add( "TXSSO Dissectors无对应SSO版本" );
      end
    end
    off = off + 2 + 2 + len;
  end
end