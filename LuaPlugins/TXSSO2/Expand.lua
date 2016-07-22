--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Expand
-------- -------- -------- --------

]=======]



local dissectors = require "TXSSO2/Dissectors";

local proto = require "TXSSO2/Proto";

local keychain = require "TXSSO2/KeyChain";

local fields = require "TXSSO2/Fields";
local fieldsex, fields = unpack( fields );

local tagname = require "TXSSO2/TagName";
local aly_lvl = require "TXSSO2/AnalysisLevel";

function dissectors.format_qqbuf( buf, off )
  local data, size = FormatEx.wxline_string( buf, off );
  local ss = string.format( "(%04X)%s", #data, data:sub( 1, 0x18 ):hex2str() );
  if #data > 0x18 then
    ss = ss .. "...";
  end
  return ss, size;
end

function dissectors.format_qqstring( buf, off )
  local data, size = FormatEx.wxline_string( buf, off );
  local ss = string.format( "(%04X)%s", #data, data:sub( 1, 0x18 ) );
  if #data > 0x18 then
    ss = ss .. "...";
  end
  return ss, size;
end

function dissectors.format_time( buf, off )
  local t = buf( off, 4 ):uint();
  local ss = os.date('%Y/%m/%d %H:%M:%S', t) .. string.format( '(0x%08X)', t );
  return ss, 4;
end

function dissectors.keyframe( root, n )
  root:add( fieldsex.keyframe.field, n );
end

function dissectors.add( ... )
  return TreeAddEx( fieldsex, ... );
end

function dissectors.addex( t, buf, off, size )
  if size <= 0 then
    return off;
  end
  return TreeAddEx( fieldsex, t, buf, off, ">unsolved", size );
end

function dissectors.TeanDecrypt( data )
  local refkeyname,refkey, ds;
  for k, v in pairs( keychain ) do
    ds = TeanDecrypt( data, v );
    if ds ~= nil and #ds > 0 then
      refkeyname = k;
      refkey = v;
      break;
    end
  end
  return refkeyname,refkey, ds;
end

function dissectors.dis_tlv( buf, pkg, root, t, off, size )
  local oo = off;
  
  local lvl = aly_lvl();

  while off - oo < size do
    local tag = buf( off + 0, 2 ):uint();
    local len = buf( off + 2, 2 ):uint();
    local tags = tagname[ tag ] or "UnknownTag";
    local info = string.format( ">>TLV_%04X_%-20s     lenght : %04X", tag, tags, len );

    local tt = t:add( proto, buf( off, 2 + 2 + len ), info );
    if lvl >= alvlC then
      local func = dissectors.tlv;
      if func then
        func = func[ tag ];
        if func then
          if not pcall( func, buf, pkg, root, tt, off + 2 + 2, len ) then
            TreeAddEx( fieldsex, tt, buf( off + 2 + 2, len ), ">unsolved", len );
          end
        else
          root:add( proto, "TXSSO Dissectors无对应TLV" .. string.format( "%04X", tag ) );
        end
      else
        root:add( proto, "TXSSO Dissectors无TLV" );
      end
    end
    off = off + 2 + 2 + len;
  end
end