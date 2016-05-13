--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TagName
-------- -------- -------- --------
返回常量表
]=======]

local TagName =
  {
  [0x0004] = "NonUinAccount",
  [0x0005] = "Uin",
  [0x0006] = "TGTGT",
  [0x0007] = "TGT",
  [0x0008] = "TimeZone",
  [0x000A] = "ErrorInfo",
  [0x000C] = "PingRedirect",
  [0x0015] = "ComputerGuid",
  [0x0017] = "ClientInfo",
  [0x0018] = "Ping",
  [0x001A] = "GTKeyTGTGTCryptedData",
  [0x001E] = "GTKey_TGTGT",
  [0x001F] = "DeviceID",
  [0x002D] = "LocalIP",
  [0x0032] = "QdData",
  [0x0036] = "LoginReason",
  [0x0100] = "ErrorCode",
  [0x0102] = "Official",
  [0x0103] = "SID",
  [0x0105] = "m_vec0x12c",
  [0x0107] = "TicketInfo",
  [0x0108] = "AccountBasicInfo",
  [0x0109] = "0xddReply",
  [0x010B] = "QDLoginFlag",
  [0x010D] = "SigLastLoginInfo",
  [0x0110] = "SigPic",
  [0x0112] = "SigIP2",
  [0x0114] = "DHParams",
  [0x0115] = "PacketMd5",
  [0x0309] = "Ping_Strategy",
  [0x030F] = "ComputerName",
  [0x0310] = "ServerAddress",
  [0x0312] = "Misc_Flag",
  [0x0313] = "GUID_Ex",
  };
return
  setmetatable( TagName,
    {
    __newindex =  function()
        return error "TXSSO2 TageName不允许修改";
      end
    }
    );

















































































































