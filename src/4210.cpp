#include <xlib.h>

#include "lua.hpp"

#include <fstream>
#include <iostream>

using namespace std;

//借助wireshark加载init.lua，而它加载consloe.lua时，嵌入加载机会
extern "C" void load_lua_plugins(lua_State* ls)
  {
  static bool lua_plugins_loaded = false;
  if(lua_plugins_loaded)  return;

  lua_plugins_loaded = true;

  const auto oldtop = lua_gettop(ls);

  lua_getglobal(ls, "Proto");           //判定是否处于wireshark环境中
  if(lua_type(ls, -1) == LUA_TNIL)
    {
    lua_settop(ls, oldtop);
    return;
    }
  lua_settop(ls, oldtop);

  HMODULE hmod = nullptr;
  GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)load_lua_plugins, &hmod);
  char name[MAX_PATH];
  GetModuleFileNameA(hmod, name, sizeof(name));

  char drive[_MAX_DRIVE];
  char dir[_MAX_DIR];
  char fname[_MAX_FNAME];
  char ext[_MAX_EXT];

  auto en = _splitpath_s(name, drive, dir, fname, ext);
  if(0 != en) return;                   //路径解析失败

  const string path(string(drive) + string(dir) + "LuaPlugins\\");

  //附加加载路径
  lua_settop(ls, oldtop);
  xmsg cmd;
  cmd << "package.path = package.path .. [[;" << path << "?.lua]];";
  luaL_dostring(ls, cmd.c_str());
  lua_settop(ls, oldtop);

  const string fn(path + "*.luae");

  WIN32_FIND_DATAA fd;
  HANDLE hf = FindFirstFileA(fn.c_str(), &fd);
  if(hf == INVALID_HANDLE_VALUE)        //文件查找失败
    return;
  do 
    {
    const string ff(path + fd.cFileName);
    lua_settop(ls, oldtop);

    if(LUA_OK != luaL_loadfile(ls, ff.c_str()) || LUA_OK != lua_pcall(ls, 0, LUA_MULTRET, 0))
      {
      lua_error(ls);
      }

    lua_settop(ls, oldtop);
    }while(FindNextFileA(hf, &fd));
  FindClose(hf);
  }

/*
lauxlib.c
  luaL_loadfilex      

linit.c
  loadedlibs          添加xlualib初始化

lstrlib.c             添加string.pack、string.unpack功能

luaconf.h
  LUA_UNSIGNED        修改使pack、unpack正确

*/