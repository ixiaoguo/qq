--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> ECDHKey
-------- -------- -------- --------
这是SSO2默认的ECDH Key。至于固定Key的方法，嘿嘿，不考虑放出

返回表，表中有二值，分别是sharekey、privatekey
]=======]
local sharekey    = "02 78 28 16 7C 9E F3 B7 5A 7B 5A EF A2 30 10 EC 0C 46 87 70 76 31 A7 88 EA";
local privatekey  = "60 42 3B 51 C3 B1 F6 0F 67 E8 9C 00 F0 A7 BD A3 DE 69 0A BD EE A1 EB A6";

return { sharekey:str2hexs(), privatekey:str2hexs() };