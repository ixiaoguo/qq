--[=======[
-------- -------- -------- --------
         自定义格式化
-------- -------- -------- --------
--FormatEx提供通用的自定义格式化操作，被TreeAddEx使用
]=======]

--[=======[
●
  uint8;              --0x00(0)
  uint16;             --0x0000(0)
  uint24;             --0x000000(0)
  uint32;             --0x00000000(0)
  uint64;             --0x0000000000000000(0)
  int8;               --0x00(0)
  int16;              --0x0000(0)
  int24;              --0x000000(0)
  int32;              --0x00000000(0)
  int64;              --0x0000000000000000(0)

  bool;               --true|false
  ipv4;               --0.0.0.0
  ipv4_port;          --0.0.0.0:0
  float;              --0.0
  string;             --00000
  bytes;              --000000

  stringz;

  bxline_string;      bline_string;
  wxline_string;      wline_string;
  dxline_string;      dline_string;
  
  bxline_bytes;       bline_bytes;
  wxline_bytes;       wline_bytes;
  dxline_bytes;       dline_bytes;
]=======]

FormatEx = { };
function FormatEx.uint8( tvb, off )
  local v = tvb( off, 1 ):uint();
  return string.format( "0x%02X(%u)", v, v ), 1;
end
function FormatEx.uint16( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 2 ):le_uint();
  else
    v = tvb( off, 2 ):uint();
  end
  return string.format( "0x%04X(%u)", v, v ), 2;
end
function FormatEx.uint24( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 3 ):le_uint();
  else
    v = tvb( off, 3 ):uint();
  end
  return string.format( "0x%06X(%u)", v, v ), 3;
end
function FormatEx.uint32( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 4 ):le_uint();
  else
    v = tvb( off, 4 ):uint();
  end
  return string.format( "0x%08X(%u)", v, v ), 4;
end
function FormatEx.uint64( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 8 ):le_uint64();
  else
    v = tvb( off, 8 ):uint64();
  end
  return "0x" .. v:tohex() .. '(' .. v .. ')', 8;
end

function FormatEx.int8( tvb, off )
  local v = tvb( off, 1 ):int();
  return string.format( "0x%02X(%d)", v, v ), 1;
end
function FormatEx.int16( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 2 ):le_int();
  else
    v = tvb( off, 2 ):int();
  end
  return string.format( "0x%04X(%d)", v, v ), 2;
end
function FormatEx.int24( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 3 ):le_int();
  else
    v = tvb( off, 3 ):int();
  end
  return string.format( "0x%06X(%d)", v, v ), 3;
end
function FormatEx.int32( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 4 ):le_int();
  else
    v = tvb( off, 4 ):int();
  end
  return string.format( "0x%08X(%d)", v, v ), 4;
end
function FormatEx.int64( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 8 ):le_int64();
  else
    v = tvb( off, 8 ):int64();
  end
  return "0x" .. v:tohex() .. '(' .. v .. ')', 8;
end

function FormatEx.bool( tvb, off )
  local v = tvb( off, 1 ):int();
  if v == 0 then
    return "false", 1;
  end
  return "true", 1;
end

function FormatEx.ipv4( tvb, off, size, func, root )
  if func and func ~= root.add then    
    return tvb( off + 3, 1 ):uint() .. '.' ..
           tvb( off + 2, 1 ):uint() .. '.' ..
           tvb( off + 1, 1 ):uint() .. '.' ..
           tvb( off + 0, 1 ):uint(),
           4;
  end
  return tvb( off + 0, 1 ):uint() .. '.' ..
         tvb( off + 1, 1 ):uint() .. '.' ..
         tvb( off + 2, 1 ):uint() .. '.' ..
         tvb( off + 3, 1 ):uint(),
         4;
end

function FormatEx.ipv4_port( tvb, off, size, func, root )
  local ss, size = FormatEx.ipv4( tvb, off, size, func, root );
  if func and func ~= root.add then
    return ss .. ':' .. tvb( off + size, 2 ):le_uint(), size + 2;
  end
  return ss .. ':' .. tvb( off + size, 2 ):uint(),
         size + 2;
end

function FormatEx.float( tvb ,off )
  return tvb( off, 4 ):float(), 4;
end

function FormatEx.string( tvb ,off, size )
  if size == nil then
    return tvb:raw( off ), tvb:len() - off;
  end
  return tvb:raw( off, size ), size;
end

function FormatEx.bytes( tvb, off, size )
  if size == nil then
    return tvb:raw( off ):hex2str(), tvb:len() - off;
  end
  return tvb:raw( off, size ):hex2str(), size;
end

function FormatEx.stringz( tvb, off )
  local e = off;
  local len = tvb:len();
  while e < len do
    if tvb( e, 1 ):uint() == 0 then
      local size = e - off;
      return tvb:raw( off, size ), size + 1; 
    end
    e = e + 1;
  end
  local size = len - off;
  return tvb:raw( off, size ), size;
end

local function get_line_string( ls, x, tvb, off, size, func, root )
  if x then
    x = 0;
  else
    x = ls;
  end
  local size;
  if func and func ~= root.add then
    size = tvb( off, ls ):le_uint();
  else
    size = tvb( off, ls ):uint();
  end
  return tvb:raw( off + ls, size - x ), size + ls - x;
end

function FormatEx.bxline_string( tvb, off, size, func, root )
  return get_line_string( 1, true, tvb, off, size, func, root );
end
function FormatEx.bline_string( tvb, off, size, func, root )
  return get_line_string( 1, false, tvb, off, size, func, root );
end
function FormatEx.wxline_string( tvb, off, size, func, root )
  return get_line_string( 2, true, tvb, off, size, func, root );
end
function FormatEx.wline_string( tvb, off )
  return get_line_string( 2, false, tvb, off, size, func, root );
end
function FormatEx.dxline_string( tvb, off, size, func, root )
  return get_line_string( 4, true, tvb, off, size, func, root );
end
function FormatEx.dline_string( tvb, off )
  return get_line_string( 4, false, tvb, off, size, func, root );
end

local function get_line_bytes( ls, x, tvb, off, size, func, root )
  if x then
    x = 0;
  else
    x = ls;
  end
  local size;
  if func and func ~= root.add then
    size = tvb( off, ls ):le_uint();
  else
    size = tvb( off, ls ):uint();
  end
  return tvb:raw( off + ls, size - x ):hex2str(), size + ls - x;
end

function FormatEx.bxline_bytes( tvb, off, size, func, root )
  return get_line_bytes( 1, true, tvb, off, size, func, root );
end
function FormatEx.bline_bytes( tvb, off, size, func, root )
  return get_line_bytes( 1, false, tvb, off, size, func, root );
end
function FormatEx.wxline_bytes( tvb, off, size, func, root )
  return get_line_bytes( 2, true, tvb, off, size, func, root );
end
function FormatEx.wline_bytes( tvb, off )
  return get_line_bytes( 2, false, tvb, off, size, func, root );
end
function FormatEx.dxline_bytes( tvb, off, size, func, root )
  return get_line_bytes( 4, true, tvb, off, size, func, root );
end
function FormatEx.dline_bytes( tvb, off )
  return get_line_bytes( 4, false, tvb, off, size, func, root );
end