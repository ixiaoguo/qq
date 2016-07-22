--[=======[
-------- -------- -------- --------
         TreeAddEx操作
-------- -------- -------- --------
]=======]

--[=======[
●
    int       TreeAddEx                 (
                                        table     protofieldsex,
                                        TreeItem  root,
                                        Tvb       tvb,
                                        int       off,
                                        ...
                                        );                                 [-4+, +1, v]
        --根据要求自动生成树元素
        --protofieldsex为ProtoFieldEx返回的第一个表
        --不定参以 short_abbr[, size|format_function], short_abbr, ... 形式提供
          当不提供size或format_function时，使用默认长度
          当指定field未有默认长度时，使用剩余的所有数据
          当指定size <= 0时，跳过不处理
          默认长度列表如下：          
            {
            uint8     = 1,
            uint16    = 2,
            uint24    = 3,
            uint32    = 4,
            uint64    = 8,
            int8      = 1,
            int16     = 2,
            int24     = 3,
            int32     = 4,
            int64     = 8,

            framenum  = 4,
            bool      = 1,
            absolute_time = 4,
            relative_time = 4,

            ipv4      = 4,
            ipv6      = 16,
            ether     = 6,
            float     = 4,
            double    = 8,
            };
        --abbr_name的第一个字符允许为'<'或'>'，用于标示field的大小端，默认大端
        --abbr_name允许以空格分隔注释。空格以后的所有数据被认为是注释而无视之
        --函数返回处理结束后的off
        --当提供format_function时，函数以如下形式调用
          format_function( buf, off, nil, tree_add_func, root, field );
          如果调用内部使用了tree_add_func，应返回off + size
          否则应返回formatted_string, size。
          处理将在其后自动调用tree_add_func( root, field, buf( off, size), formatted_string );

        --允许指定abbr_name在protofieldsex中无匹配，此时有如下规则
          --当提供format_function时，函数以如下形式调用
            format_function( buf, off, nil, tree_add_func, root, field );
            如果调用内部使用了tree_add_func，应返回off + size
            否则应返回formatted_string, size。
            处理将在其后自动调用tree_add_func( root, buf( off, size), prefix_string .. formatted_string );
          --否则必须在空格后指定类型，支持类型参考FormatEx

        ex:
          off = TreeAddEx( fieldsex, root, tvb, off,
            "xxoo_b",                   --可识别的short_abbr，且可识别长度
            "xx", 2,                    --强制长度
            "xxoo_s", format_xxx        --可识别的short_abbr，但不可识别长度，需要自定义格式化
            );
          --生成效果大致如下：
          xxoo_b        Byte      :0x00
          xx            xx        :0x0000(0)
          xxoo_s        String    :xxxxxxxx

        ex:
          TreeAddEx( fieldsex, root, tvb, off,
            "*xxoo_b uint8",            --指定可识别的支持类型，不用后续指定大小
            "*xxoo_s string", 6,        --支持类型可识别，但强制指定大小
            "*xxoo_a", 5                --不指定类型，默认bytes
            );
          --生成效果大致如下：
          -             *xxoo_b   :0x00(0)
          -             *xxoo_s   :xxxxxx
          -             *xxoo_a   :##########
]=======]

-------- -------- -------- -------- 
local TypeDefaultSize =
  {
  uint8     = 1,
  uint16    = 2,
  uint24    = 3,
  uint32    = 4,
  uint64    = 8,
  int8      = 1,
  int16     = 2,
  int24     = 3,
  int32     = 4,
  int64     = 8,

  framenum  = 4,
  bool      = 1,
  absolute_time = 4,
  relative_time = 4,

  ipv4      = 4,
  ipv6      = 16,
  ether     = 6,
  float     = 4,
  double    = 8,
  };
-------- -------- -------- -------- 
local FieldShort =
  {
  b   = "uint8",
  w   = "uint16",
  d   = "uint32",
  q   = "uint64",
  a   = "bytes",
  s   = "string",

  B   = "uint8",
  W   = "uint16",
  D   = "uint32",
  Q   = "uint64",
  A   = "bytes",
  S   = "string",
  };

local function TreeAddEx_AddOne( arg, k, root, tvb, off, protofieldsex )
  local abbr = arg[ k ];      k = k + 1;

  local func = root.add;
  --判定大小端
  local isnet = abbr:sub(1, 1);
  if isnet == '<' then
    func = root.add_le;
    abbr = abbr:sub( 2 );
  elseif isnet == '>' then
    abbr = abbr:sub( 2 );
  end

  local abbr, fmttype = abbr:match( "([^ ]+) *([^ ]*)" );

  --尝试类型简写转换
  if FieldShort[ fmttype ] then
    fmttype = FieldShort[ fmttype ];
  end

  --空串忽略
  if not abbr or abbr == "" then
    return off, k;
  end

  local tb = protofieldsex[abbr];
  local field;
  if tb then
    field = tb.field;
  else
    --当abbr不可识别时，field为伪前缀
    field = string.format( protofieldsex.__fmt, "-", abbr:utf82s() ):s2utf8();
  end

  local kk = arg[ k ];
  local types = type( kk );
  --如果有指定格式化函数，则使用之
  if types == "function" then
    local ss, size = kk( tvb, off, nil, func, root, field );
    --如果格式化函数内部处理完毕，则不再继续
    if not size or size <= 0 then
      return ss, k + 1;
    end
    --否则进行默认添加
    if tb then
      func( root, field, tvb( off, size ), ss );
    else
      func( root, tvb( off, size ), field .. ss );
    end
    return off + size, k + 1;
  end

  if tb then
    if types == "number" then
      if kk <= 0 then
        return off, k + 1;
      end
      func( root, tb.field, tvb( off, kk ) );
      return off + kk, k + 1;
    end
    
    --如果未有指定，则尝试使用默认大小
    local size = TypeDefaultSize[ tb.types ];
    if size then
      func( root, field, tvb( off, size ) );
      return off + size, k;
    end

    --如果没有指定大小，也未指定类型或格式化，直接输出
    if not fmttype or fmttype == "" then
      func( root, field, tvb( off ) );
      return tvb:len(), k;
    end

    --尝试识别指定类型，如果指定类型不可识别，则使用abbr的类型或bytes
    fmttype = FormatEx[ fmttype ];
    if not fmttype then
      fmttype = FormatEx[ tb.types ] or FormatEx.bytes;
    end
    
    local ss, size = fmttype( tvb, off, nil, func, root, field );
    if not size or size <= 0 then
      return ss, k;
    end
    func( root, field, tvb( off, size), ss );
    return off + size, k;
  end

  --abbr不可识别时，除非另外指定格式化函数，否则必须指定类型，且类型可格式化
  local tps = fmttype;
  if not fmttype or fmttype == "" then
    return error( "abbr:" .. abbr .. " no fixed and no type" );
  end
  if not FormatEx[ fmttype ] then
    return error( "abbr:" .. abbr .. ", type:" .. fmttype .. " no fixed and type unknown" );
  end
  fmttype = FormatEx[ fmttype ];

  --如果有指定大小，则使用指定大小
  if types == "number" then
    local size = kk;
    local ss, size = fmttype( tvb, off, size, func, root, field );
    if not size or size <= 0 then
      return ss, k + 1;
    end
    func( root, tvb( off, size ), field .. ss );
    return off + size, k + 1;
  end
  
  local ss, size = fmttype( tvb, off, nil, func, root, field );
  if not size or size <= 0 then
    return ss, k;
  end
  func( root, tvb( off, size ), field .. ss );
  return off + size, k;
end

function TreeAddEx( protofieldsex, root, tvb, off, ... )
  local off = off or 0;
  local arg = { ... };

  local k = 1;
  while k <= #arg do
    off, k = TreeAddEx_AddOne( arg, k, root, tvb, off, protofieldsex );
    if off >= tvb:len() then
      break;
    end
  end
  return off;
end