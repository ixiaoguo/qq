--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Fields
-------- -------- -------- --------

返回表：表中二值，分别是fieldsex、fields
]=======]

local CsCmdNo = require "TXSSO2/CsCmdNo";
local PubNo = require "TXSSO2/PubNo";
local fields =
  {
    { "bytes",      "unsolved",       "未解决"                   },
    
    { "uint8",      "cPreFix",        "协议前缀",       base.HEX },
    { "uint8",      "cSufFix",        "协议后缀",       base.HEX },
    { "uint8",      "cMainVer",       "SSO主版本",      base.HEX },
    { "uint8",      "cSubVer",        "SSO次版本",      base.HEX },
    { "uint16",     "wCsCmdNo",       "指令",           base.HEX, CsCmdNo },
    { "uint16",     "wCsIOSeq",       "包序",           base.HEX },
    { "uint32",     "dwUin",          "QQ号",           base.DEC },
    { "uint32",     "dwClientType",   "客户端类型",     base.HEX },
    { "uint32",     "dwPubNo",        "发行版本号",     base.HEX, PubNo },
    { "uint16",     "wTlvVer",        "TLV版本号",      base.HEX },
    { "uint32",     "dwSSOVersion",   "SSO版本号",      base.HEX },
    { "uint32",     "dwServiceId",    "ServiceId",      base.HEX },
    { "uint32",     "dwClientVer",    "客户端版本",     base.HEX },
    { "uint16",     "wRedirectCount", "重定向次数",     base.DEC },
    { "uint8",      "cRedirectCount", "重定向次数",     base.DEC },
    { "ipv4",       "dwRedirectIP",   "重定向IP"                 },
    { "ipv4",       "dwServerIP",     "服务器IP"                 },
    { "uint8",      "cPingType",      "PingType",       base.HEX },
    { "bytes",      "bufCsPrefix",                               },
  };

local fieldsex, fields = ProtoFieldEx( "txsso2.", fields );

return
  {
  setmetatable(
    fieldsex,
    {
    __newindex = function()
      return error "TXSSO2 fieldsex禁止修改";
    end
    }
    ),
  setmetatable(
    fields,
    {
    __newindex = function()
      return error "TXSSO2 fields禁止修改";
    end
    }
    )
  };