--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Dissectors
-------- -------- -------- --------

解析函数总表

返回表
]=======]

local dissectors = {};

dissectors.other = {};

--如果只是版本不同，解析方法相同，只需要简单的=就好啦
dissectors[0x3649] = dissectors.other;
dissectors[0x3613] = dissectors.other;
dissectors[0x3625] = dissectors.other;

return dissectors;