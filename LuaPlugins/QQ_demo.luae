--[=======[
-------- -------- -------- --------
           QQ Demo插件
-------- -------- -------- --------
]=======]
--[=======[
●-------- -------- 解析等级控制 -------- --------
  string      qq_analysis_level = "detail";
    --默认解析等级首先接受全局解析等级控制main_analysis_level
    --允许实时改变qq的解析等级以单独控制
]=======]
local qq_default_analysis_level = "detail";
qq_analysis_level = main_analysis_level or qq_default_analysis_level;

local aly_lvl = analysis_level_tables[qq_analysis_level];

-------- -------- 协议字段 -------- --------
local common_fields =
  {
    { "bytes",      "unsolved",       "未解决"                    },
  };

--[=======[
-------- -------- -------- --------
       QQ UDP解析部分
-------- -------- -------- --------
]=======]

--[=======[
●
  filter      qq_udp                  --以此filter单独提取qq udp部分
]=======]

local proto = Proto( "QQ_UDP", "QQ UDP Protocol" );
local proto_port = 8000;
-------- -------- 指令类型 -------- --------
local cmd =
  {
  [0x0825] = "Ping",
  [0x0836] = "CheckTGTGT",
  [0x0828] = "PreLogin",
  }
local cmds = {};    for k, v in pairs(cmd) do cmds[v] = k; end

local Packet_PreFix = '\x02';
local Packet_SufFix = '\x03';
-------- -------- 协议字段 -------- --------
local fields =
  {
    { "uint8",      "cMainVer",       "SSO主版本",      base.HEX },
    { "uint8",      "cSubVer",        "SSO次版本",      base.HEX },
    { "uint16",     "wCsCmdNo",       "指令",           base.HEX, cmd },
    { "uint16",     "wCsIOSeq",       "包序",           base.HEX },
    { "uint32",     "dwUin",          "QQ号",           base.DEC },
    { "uint32",     "dwClientType",   "客户端类型",     base.HEX },
    { "uint32",     "dwPubNo",        "PubNo",          base.HEX },
    { "bytes",      "bufCsPrefix",                               },
    

  };
for _, v in pairs( common_fields ) do
  fields[ #fields + 1 ] = v;
end
local fieldsex, fields = ProtoFieldEx( "qq.udp.", fields );
proto.fields = fields;

-------- -------- 解析函数组 -------- --------
local dissector = {};
dissector.send = {};
dissector.recv = {};

local sends = dissector.send;
local recvs = dissector.recv;

local function fix_dissector( buf, t, off, size, ... )
  local o = TreeAddEx( fieldsex, t, buf, off, ... );
  local on = off + size;
  if o >= on then
    return;
  end
  TreeAddEx( fieldsex, t, buf, o, "unsolved", on - o );
end

function sends.Ping( buf, pkg, root, t, off, size )
  local oldoff = off;
  local tt = t:add( proto, buf(off, 0xA), "bufPacketHeader");
  local off = TreeAddEx( fieldsex, tt, buf, off,
    ">cMainVer B",
    ">cSubVer B",
    ">wCsCmdNo W",
    ">wCsIOSeq W",
    ">dwUin D"
    );
    --[[
  local off = TreeAddEx( fieldsex, t, buf, off,
    ">xxoo_a", 3,
    ">dwClientType D",
    ">dwPubNo D",
    ">xxoo_d"
    );
    ]]
  local key = buf:raw( off, 0x10 );
  local off = TreeAddEx( fieldsex, t, buf, off,
    ">bufCsPrefix", 0x10
    );
  local rest = size - off + oldoff;
  local data = buf:raw( off, rest );
  data = data:tean_dec( key );
  data = ByteArray.new( data, true ):tvb( "Data" );
  t:add( buf(off, rest ),
    string.format("GeneralCodec_Request [%04X] >> [%04X]", rest, data:len() )
    );
end

function dissector.other( buf, pkg, root, t, off, size )
  if aly_lvl ~= alvlD then
    return;
  end
  fix_dissector( buf, t, off, size );
end


local function proto_chk( buf )
  local len = buf:len();
  if len < 1 + 1 + 6 then
    return false;
  end
  if buf:raw(0, 1) ~= Packet_PreFix then
    return false;
  end
  if buf:raw(len-1, 1) ~= Packet_SufFix then
    return false;
  end
  return true;
end


local OldDissector = DissectorTable.get("udp.port"):get_dissector( proto_port );
function proto.dissector( buf, pkg, root )
  if not proto_chk( buf ) then
    if not OldDissector then
      return;
    end
    return OldDissector( buf, pkg, root );
  end
  
  local dis_func = dissector.send;
  if pkg.src_port == proto_port then
    dis_func = dissector.recv;
  end

  pkg.cols.protocol:set( proto.name );
  
  local lcmd = buf(1 + 1 + 1, 2):uint();
  local lcmds = cmd[lcmd] or "???";
  local ss = string.format( "-%04X-%s-", lcmd, lcmds );
  if pkg.dst_port == proto_port then
    ss = "●" .. ss;
  else
    ss = "○" .. ss;
  end
  pkg.cols.info:set( ss );

  local t = root:add( proto, buf(), "QQ UDP     CMD : " .. ss );

  local size = buf:len() - 1 - 1;
  if size > 0 then
    local func = dis_func[ lcmds ] or dissector.other;
    func( buf, pkg, root, t, 1, size );
  end
  
end

DissectorTable.get("udp.port"):add( proto_port, proto );