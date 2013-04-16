#ifndef __TRACEBOX_LUA_H__
#define __TRACEBOX_LUA_H__

#include <lua.h>

int tracebox_lua_load(const char *file);
int tracebox_lua_run(const char *cmd);

#endif
