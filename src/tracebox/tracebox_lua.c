#include "tracebox_lua.h"
#include "libtracebox/tracebox.h"

#include <lualib.h>
#include <lauxlib.h>
#include <string.h>

#define error(format, args...)  \
	fprintf(stderr, format "\n", ## args)

#define parse_opt(name, type, field) do { \
	lua_getfield(L, 2, #name); \
	if (lua_type(L, -1) != type) \
		break; \
	switch (type) { \
	case LUA_TNUMBER: {\
		int __i = lua_tointeger(L, -1); \
		memcpy(field, &__i, sizeof(field)); \
		break; \
		} \
	case LUA_TSTRING: {\
		const char *__s = lua_tostring(L, -1); \
		memcpy(field, &__s, sizeof(field)); \
		break; \
		} \
	} \
} while (0)

static int tracebox_lua(lua_State *L)
{
	tbox_conf_t tbox = TBOX_DEFAULT;
	tbox_res_t res[TBOX_HARD_TTL+1];
	uint8_t *probe;
	size_t probe_len = 0;

	int n = lua_gettop(L);
	if (n != 2)
	    return luaL_error(L, "Got %d arguments expected 2", n);

	if (!lua_isstring(L, 1)) {
		lua_pushstring(L, "Incorrect argument to 'tracebox'");
		lua_error(L);
	}
	probe = (uint8_t *)lua_tolstring(L, 1, &probe_len);

	if (lua_istable(L, 2)) {
		parse_opt(iface, LUA_TSTRING, &tbox.iface);
		parse_opt(min_ttl, LUA_TNUMBER, &tbox.min_ttl);
		parse_opt(max_ttl, LUA_TNUMBER, &tbox.max_ttl);
		parse_opt(nprobes, LUA_TNUMBER, &tbox.nprobes);
		parse_opt(probe_timeo, LUA_TNUMBER, &tbox.probe_timeo);
		parse_opt(noreply, LUA_TNUMBER, &tbox.noreply);
	}
	return tracebox(probe, probe_len, res, 0);
}

static void luaopen_tracebox(lua_State *L)
{
	lua_register(L, "tracebox", tracebox_lua);
}

LUALIB_API int luaopen_net (lua_State *L);

static lua_State *tracebox_lua_init(void)
{
	lua_State *L = lua_open();
	luaL_openlibs(L);
	luaopen_net(L);
	luaopen_tracebox(L);
	return L;
}

int tracebox_lua_load(const char *file)
{
	int ret = 0;
	lua_State *L = tracebox_lua_init();

	ret = luaL_dofile(L, file);
	if (ret != 0)
		error("Script error: %s", lua_tostring(L, -1));
	lua_close(L);
	return ret;
}

int tracebox_lua_run(const char *cmd)
{
	int ret = 0;
	lua_State *L = tracebox_lua_init();

	ret = luaL_dostring(L, cmd);
	if (ret != 0)
		error("Command error: %s", lua_tostring(L, -1));
	lua_close(L);
	return ret;
}
