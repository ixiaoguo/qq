--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Fields
-------- -------- -------- --------

返回表：表中二值，分别是fieldsex、fields
]=======]

local CsCmdNo = require "TXSSO2/CsCmdNo";
local PubNo = require "TXSSO2/PubNo";
local RetCode = require "TXSSO2/RetCode";

local fields =
  {
    { "bytes",        "unsolved",               "未解决"                       },
    
    { "string",       "NullBuf",                                               },
    { "string",       "UnknowBuf",                                             },
    
    { "uint8",        "cPreFix",                "协议前缀",           base.HEX },
    { "uint8",        "cSufFix",                "协议后缀",           base.HEX },
    { "uint8",        "cMainVer",               "SSO主版本",          base.HEX },
    { "uint8",        "cSubVer",                "SSO次版本",          base.HEX },
    { "uint16",       "wCsCmdNo",               "指令",               base.HEX, CsCmdNo },
    { "uint16",       "wCsIOSeq",               "包序",               base.HEX },
    { "uint32",       "dwUin",                  "QQ号",               base.DEC },
    { "bytes",        "bufCsPrefix",                                           },
    { "uint32",       "dwClientType",           "客户端类型",         base.HEX },
    { "uint32",       "dwPubNo",                "发行版本号",         base.HEX, PubNo },
    { "uint16",       "wTlvVer",                "TLV版本号",          base.HEX },
    { "uint32",       "dwSSOVersion",           "SSO版本号",          base.HEX_DEC },
    { "uint32",       "dwServiceId",            "ServiceId",          base.HEX },
    { "uint32",       "dwClientVer",            "客户端版本",         base.HEX_DEC },
    { "uint16",       "wRedirectCount",         "重定向次数",         base.DEC },
    { "uint8",        "cRedirectCount",         "重定向次数",         base.DEC },
    { "ipv4",         "dwRedirectIP",           "重定向地址"                   },
    { "ipv4",         "dwServerIP",             "服务器地址"                   },
    { "uint8",        "cPingType",              "PingType",           base.HEX },
    { "string",       "bufDHPublicKey",         "ECDHPublicKey"                },
    { "uint8",        "cResult",                "响应码",             base.HEX, RetCode },
    { "bytes",        "bufSigClientAddr",                                      },
    { "absolute_time","dwServerTime",           "服务器时间",         base.LOCAL },
    { "ipv4",         "dwClientWanIP",          "客户端外网地址"               },
    { "uint16",       "wClientWanPort",         "客户端外网端口",     base.DEC_HEX },
    { "uint32",       "dwIDC",                  "IDC",                base.HEX },
    { "uint32",       "dwISP",                  "ISP",                base.HEX },
    { "uint16",       "wRedirectPort",          "重定向端口",         base.DEC_HEX },
    { "string",       "ComputerName",           "计算机名称"                   },
    { "string",       "bufComputerID",          "机器码"                       },
    { "bool",         "bRememberPwdLogin",      "记住密码"                     },
    { "bytes",        "bufPsMD5",               "密码MD5"                      },
    { "bytes",        "bufTGTGTKey",            "TGTGTKey"                     },
    { "string",       "bufSID",                 "SID"                          },
    { "bytes",        "bufOfficialKey",         "OfficialKey"                  },
    { "string",       "bufSigPic",              "SigPic"                       },
    { "bytes",        "bufOfficial",            "Official"                     },
    { "uint32",       "crc32",                  "CRC32",              base.HEX },
    { "bytes",        "bufPacketMD5",           "PacketMD5"                    },
    { "bytes",        "bufSessionKey",          "SessionKey"                   },
    { "string",       "bufSession",             "Session"                      },
    { "string",       "bufPwdForConn",          "PwdForConn"                   },
    { "string",       "bufBill",                "Bill"                         },
    { "uint32",       "dwTGTServiceID",         "TGTServiceID",       base.HEX },
    { "uint32",       "dwTGTPriority",          "TGT优先权值",        base.HEX },
    { "relative_time","dwTGTRefreshInterval",   "TGT刷新间隔"                  },
    { "relative_time","dwTGTValidInterval",     "TGT有效时长"                  },
    { "relative_time","dwTGTTryInterval",       "TGT尝试间隔"                  },
    { "uint16",       "wTGTTryCount",           "TGT尝试次数",        base.DEC },
    { "bytes",        "bufTGT_GTKey",           "TGT_GTKey"                    },
    { "string",       "bufTGT",                 "TGT"                          },
    { "bytes",        "TGT",                    "TGT"                          },
    { "bytes",        "buf16bytesGTKey_ST",     "16bytesGTKey_ST"              },
    { "string",       "bufServiceTicket",       "ServiceTicket"                },
    { "bool",         "bAllowPtlogin",          "AllowPtlogin"                 },
    { "bytes",        "buf16bytesGTKey_STHttp", "16bytesGTKey_STHttp"          },
    { "string",       "bufServiceTicketHttp",   "ServiceTicketHttp"            },
    { "bytes",        "bufGTKey_TGTPwd",        "GTKey_TGTPwd"                 },
    { "uint16",       "wSSO_Account_wFaceIndex","头像索引",           base.HEX },
    { "string",       "strSSO_Account_strNickName","昵称"                      },
    { "uint8",        "cSSO_Account_cGender",   "性别",               base.HEX },
    { "uint32",       "dwSSO_Account_dwUinFlag","UinFlag",            base.HEX },
    { "uint8",        "cSSO_Account_cAge",      "年龄",               base.DEC },
    { "string",       "bufSTOther",             "STOther"                      },
    { "bytes",        "bufDeviceID",            "DeviceID"                     },
    { "ipv4",         "dwLocalIP",              "客户端内网地址"               },
    { "bytes",        "bufQQMd5",               "QQ客户端MD5"                  },
    { "uint8",        "QdFlag",                 "QdFlag",             base.HEX },

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