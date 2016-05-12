--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> AnalysisLevel
-------- -------- -------- --------

新建全局变量txsso2_analysis_level使外部解析等级可控

返回函数：提取当前解析等级
]=======]
--[=======[
●-------- -------- 解析等级控制 -------- --------
  string      txsso2_analysis_level = "detail";
    --默认解析等级首先接受全局解析等级控制main_analysis_level
    --允许实时改变TXSSO2的解析等级以单独控制
]=======]
local default_analysis_level = "detail";

txsso2_analysis_level = main_analysis_level or default_analysis_level;

return
  function()
    return analysis_level_tables[txsso2_analysis_level];
  end