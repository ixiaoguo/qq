--[=======[
-------- -------- -------- --------
         解析等级控制
-------- -------- -------- --------
]=======]

--[=======[
●
  string      main_analysis_level = "detail"; --全局解析等级控制，默认细度最高

    --解析等级有"simple"|"more"|"complex"|"detail"，解析细度逐层提升，解析效率逐层下降
    --解析等级允许简写："s|m|c|d|S|M|C|D"
    
●
  table       analysis_level_tables =    
    {
    simple  = 1,        s = 1,
    more    = 2,        m = 2,
    complex = 3,        c = 3,
    detail  = 4,        d = 4,
    };                                  --等级值转换

  --提供简写加速解析    
  const int   alvlS = analysis_level_tables.simple;
  const int   alvlM = analysis_level_tables.more;
  const int   alvlC = analysis_level_tables.complex;
  const int   alvlD = analysis_level_tables.detail;
]=======]

main_analysis_level = "detail";

analysis_level_tables =
  {
  simple  = 1,        s = 1,
  more    = 2,        m = 2,
  complex = 3,        c = 3,
  detail  = 4,        d = 4,
  };

alvlS = analysis_level_tables.simple;
alvlM = analysis_level_tables.more;
alvlC = analysis_level_tables.complex;
alvlD = analysis_level_tables.detail;