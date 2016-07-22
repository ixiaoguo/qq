--[=======[
-------- -------- -------- --------
         ProtoFieldEx操作
-------- -------- -------- --------
]=======]

--[=======[
●
    table protofieldsex, table protofields
              ProtoFieldEx              (
                                        [ string proto_pre_fix, ]
                                        table fields
                                        );                                [-1|2, +2, v]
        --建立自动对齐格式化的Field表
        --返回第一个表用于与TreeAddEx配合使用，简化元素添加
          {
          ["__fmt"] = fmt;
          [short_addr] = { type = func, field },
          ...
          }
        --返回第二个表用于proto.fields的赋值
          {
          [short_addr] = field,
          ...
          }
        --参数proto_pre_fix用于添加abbr前缀（强烈建议添加之）
        --fields的规则如下：
          {
            { func,         short_abbr,     name,         ... },
            ...
          };
          name允许为nil，此时，name默认使用short_abbr的内容
        --函数预先扫描全表，提取short_abbr与name各自最大长度，设定对齐格式，重新生成fix_name
          "%-##s    %-##s    "
        --对于表中每个元素，函数将为之生成
            ProtoField[ func ]( proto_pre_fix .. short_abbr, fix_name, ... );
          当func未能识别时，默认使用uint32
        --func无视大写，一律转换成小写格式
        --函数自动在表前添加如下默认元素
          {
            { "uint8",      "xxoo_b",     "Byte",    base.HEX_DEC },
            { 'uint16',     "xxoo_w",     "Word",    base.HEX_DEC },
            { 'uint32',     "xxoo_d",     "Dword",   base.HEX_DEC },
            { 'uint64',     "xxoo_q",     "Qword",   base.HEX_DEC },
            { 'bytes',      "xxoo_a",     "Array"                 },
            { "string",     "xxoo_s",     "String"                },
          };
        --表元素====允许覆盖之===
        --!!!!函数处理fix_name时，以UTF8格式处理字符串，要求short_abbr与name必须为UTF8!!!!
        --fields的func允许简写：          
          {
          b   = "uint8",
          w   = "uint16",
          d   = "uint32",
          q   = "uint64",
          a   = "bytes",
          s   = "string",
          }
]=======]
--此表用于处理简写
local ProtoFieldShort =
  {
  b   = "uint8",
  w   = "uint16",
  d   = "uint32",
  q   = "uint64",
  a   = "bytes",
  s   = "string",
  };
function ProtoFieldEx( arg1, arg2 )
  --这个表转移进来是为了在非wireshark环境下初始化时不出错
  local ProtoFieldDefault =
    {
      { "uint8",      "xxoo_b",     "Byte",       base.HEX_DEC },
      { 'uint16',     "xxoo_w",     "Word",       base.HEX_DEC },
      { 'uint32',     "xxoo_d",     "Dword",      base.HEX_DEC },
      { 'uint64',     "xxoo_q",     "Qword",      base.HEX_DEC },
      { 'bytes',      "xxoo_a",     "Array"                    },
      { "string",     "xxoo_s",     "String"                   },
    };
  --参数识别
  local pre_fix, fields;
  if type( arg2 ) == "table" then
    pre_fix = arg1;
    fields = arg2;
  else
    fields = arg1;
    pre_fix = arg2;
  end
  pre_fix = pre_fix or "";

  --复制，避免后面对原始fields表的修改
  local fs = {};
  for k, t in pairs( fields ) do
    fs[ k ] = { unpack( t ) };
  end
  fields = fs;

  --插入默认表
  for _, tb in pairs( ProtoFieldDefault ) do
    table.insert( fields, 1, tb );
  end

  --去除重复，abbr_name被重载的情况下，以最后一个为准
  local fs = {};
  for k, tb in pairs( fields ) do
    fs[ tb[ 2 ] ] = k;
  end
  
  --先获取abbr与name的最大长度，用于显示对齐
  local abbr_max = 16;
  local name_max = 16;

  for _, k in pairs( fs ) do
    local arg = fields[ k ];
    if #arg[2] > abbr_max then          --abbr必须要有
      abbr_max = #arg[2];
    end
    if arg[3] then                      --name允许没有
      arg[3] = utf82s( arg[3] );
      if #arg[3] > name_max then        --处理utf8与ascii的长度差异
        name_max = #arg[3];
      end
    end
  end
  if name_max < abbr_max then           --name的最大长度必须不小于abbr
    name_max = abbr_max;
  end
  local fmt = "%-" .. abbr_max .. "s    %-" .. name_max .. "s    ";
  
  local protofieldsex = { ["__fmt"] = fmt .. ": " };
  local protofields = {};
  --开始提取field type, abbr, name。同时修改name以使对齐显示。进而建立field
  for _, k in pairs( fs ) do
    local arg = fields[ k ];
    local func = arg[ 1 ] or "uint32";
    func = func:lower();
    func = ProtoFieldShort[ func ] or func; --简写转换

    local abbr = arg[ 2 ];
    local name = arg[ 3 ] or abbr;
    name = s2utf8( string.format( fmt, abbr, name ) );    --解决对齐问题
    
    local types = func;
    local func = ProtoField[func] or ProtoField.uint32;
    local field = func( pre_fix .. abbr, name, select( 4, table.unpack( arg ) ) );

    protofields[ abbr ] = field;
    protofieldsex[ abbr ] = { types = types,  field = field };
  end
  
  return protofieldsex, protofields;
end
