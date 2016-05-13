--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> RetCode
-------- -------- -------- --------

返回常量表
]=======]

local RetCode =
  {
  [0x00] = "成功";
  [0xFE] = "需要重定向";
  [0xFD] = "过载保护";
  [0xF8] = "DoMain";
  [0xF9] = "要求切换TCP";
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

















































































































