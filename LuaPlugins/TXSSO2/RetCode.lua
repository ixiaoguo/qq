--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> RetCode
-------- -------- -------- --------

返回常量表
]=======]

local RetCode =
  {
  [0x00] = "成功";
  [0x01] = "需要更新TGTGT";
  [0x33] = "帐号被回收";
  [0x34] = "密码错误";
  [0x3F] = "需要验证密保";
  [0xFE] = "需要重定向";
  [0xFD] = "过载保护";
  [0xF8] = "DoMain";
  [0xF9] = "要求切换TCP";
  [0xFA] = "需要重新CheckTGTGT";
  [0xFB] = "需要验证码";
  [0xFF] = "其它错误";
  };
return
  setmetatable( RetCode,
    {
    __newindex =  function()
        return error "TXSSO2 RetCode不允许修改";
      end
    }
    );

















































































































