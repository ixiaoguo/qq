echo off

rem 设置用于编译和加密的Lua程序路径
set LuaBasePath=BaseLua52

rem 合并文件脚本保存为xlua.lua，注释保存为xlua.txt
set DestLua=xlua.lua
set DestCmt=xlua.txt

rem 跳转到此BAT所在的目录
set DestPath=%CD%
%~d0
cd "%~dp0"

rem 检测当前系统平台
set NowPlatform=x86
echo %ProgramW6432% | findstr 32
if not %errorlevel%==0 set NowPlatform=x64
echo 当前系统平台 %NowPlatform%

rem 选择与当前系统平台匹配的Lua程序
set LuaExe=%LuaBasePath%\%NowPlatform%\lua52
echo Lua路径 %LuaExe%

echo 合并xlua文件...

rem 初始化合并脚本、合并注释
set xlua_ver=3.2
echo xlua_ver = %xlua_ver%>%DestLua%
echo xlua版本 %xlua_ver%>%DestCmt%

rem 合并脚本；提取注释
for /r %%f in (..\xlualib\Lua\*.lua) do echo     %%f& "%LuaExe%" -e "local file = io.open( [[%%f]], 'r'); local data = file:read('*a'); file:close(); local notes = ''; for note in data:gmatch('%%-%%-%%[=======%%[(.-)%%]=======%%]') do notes = notes .. '\r\n' .. note .. '\r\n'; end   file = io.open( '%DestLua%', 'a+'); file:write( '\r\ndo\r\n' .. data .. '\r\nend\r\n' ); file:close(); file = io.open( '%DestCmt%', 'a+'); file:write( notes ); file:close();"&if not %errorlevel%==0 echo !!!!!!!!合并失败!!!!!!!!&&goto mkerror

echo 合并wireshark ex...
set wireshark_ex_ver=3.0
echo -->>%DestLua%
echo wireshark_ex_ver = %wireshark_ex_ver%>>%DestLua%
echo -->>%DestCmt%
echo wireshark扩展版本 %wireshark_ex_ver%>>%DestCmt%

for /r %%f in (ExtendScript\*.lua) do echo     %%f& "%LuaExe%" -e "local file = io.open( [[%%f]], 'r'); local data = file:read('*a'); file:close(); local notes = ''; for note in data:gmatch('%%-%%-%%[=======%%[(.-)%%]=======%%]') do notes = notes .. '\r\n' .. note .. '\r\n'; end   file = io.open( '%DestLua%', 'a+'); file:write( '\r\ndo\r\n' .. data .. '\r\nend\r\n' ); file:close(); file = io.open( '%DestCmt%', 'a+'); file:write( notes ); file:close();"&if not %errorlevel%==0 echo !!!!!!!!合并失败!!!!!!!!&&goto mkerror

echo 合并完成

rem 根据设置，选择相应编译平台
set LuaPlatform=x64
if not "%1" == "64" set LuaPlatform=x86
echo 当前编译 %LuaPlatform% ...

rem 编译脚本
"%LuaBasePath%\%LuaPlatform%\luac52" -s -o %DestLua% %DestLua%

if not %errorlevel%==0 echo !!!!!!!!编译失败!!!!!!!!&&goto mkerror

echo 编译完成

goto end

::以下指令是故意写错，以促使VS编译进程中断
:mkerror
echo 2&>1
goto end

:end
echo ++++++++预处理结束++++++++
:eof