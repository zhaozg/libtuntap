#include <tuntap.h>

#include <lua.h>
#include <lauxlib.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#if LUA_VERSION_NUM == 501 && !defined(luaL_newlib)

#define LUA_OK 0

static void luaL_setfuncs(lua_State *L, const luaL_Reg *l, int nup)
{
    luaL_checkstack(L, nup + 1, "too many upvalues");
    for (; l->name != NULL; l++) {
        int i;
        lua_pushstring(L, l->name);
        for (i = 0; i < nup; i++) {
            lua_pushvalue(L, -(nup + 1));
        }
        lua_pushcclosure(L, l->func, nup);
        lua_settable(L, -(nup + 3));
    }
    lua_pop(L, nup);
}

static void luaL_setmetatable(lua_State *L, const char *tname)
{
    luaL_getmetatable(L, tname);
    lua_setmetatable(L, -2);
}

#define luaL_newlibtable(L,l) lua_createtable(L, 0, sizeof(l)/sizeof((l)[0]) - 1)
#define luaL_newlib(L,l) (luaL_newlibtable(L,l), luaL_setfuncs(L,l,0))

#endif


static int ltuntap_pushresult(lua_State* L, int ret)
{
    if (ret < 0)
    {
        lua_pushnil(L);
        if (errno!=0)
            lua_pushstring(L, strerror(errno));
        else
            lua_pushnil(L);
        lua_pushinteger(L, errno);
        return 3;
    }

    lua_pushinteger(L, ret);
    return 1;
}

#define TUNTAP_TNAME "tuntap.device"

typedef struct device tuntap_t;

#define CHECK_TUNTAP(i)  *(tuntap_t**)luaL_checkudata(L, (i), TUNTAP_TNAME)

static int ltuntap_read(lua_State* L)
{
    int ret = 0;

    unsigned char buf[2048];
    unsigned char* p = buf;

    tuntap_t* ltuntap = CHECK_TUNTAP(1);
    size_t len = luaL_optint(L, 2, tuntap_get_readable(ltuntap));

    if (len > sizeof(buf)) p = malloc(len);

    ret = tuntap_read(ltuntap, p, len);
    if (ret == -1)
        ret = ltuntap_pushresult(L, ret);
    else
    {
        lua_pushlstring(L, (const char*)p, ret);
        ret = 1;
    }

    if (p!=buf) free(p);
    return ret;
}

static int ltuntap_write(lua_State* L)
{
    size_t len;
    tuntap_t* ltuntap = CHECK_TUNTAP(1);
    const char* buf = luaL_checklstring(L, 2, &len);

    int ret = tuntap_write(ltuntap, (void*)buf, len);
    if (ret==-1) return ltuntap_pushresult(L, ret);

    lua_pushinteger(L, ret);
    return 1;
}

static int ltuntap_release(lua_State* L)
{
    tuntap_t* ltuntap = CHECK_TUNTAP(1);

    tuntap_release(ltuntap);
    *(tuntap_t**)lua_touserdata(L, 1) = NULL;
    return 0;
}

static int ltuntap_destroy(lua_State* L)
{
    tuntap_t* ltuntap = CHECK_TUNTAP(1);

    tuntap_destroy(ltuntap);
    *(tuntap_t**)lua_touserdata(L, 1) = NULL;
    return 0;
}

static int ltuntap_start(lua_State* L)
{
    tuntap_t* ltuntap = CHECK_TUNTAP(1);
    int mode = luaL_optint(L, 2, TUNTAP_MODE_TUNNEL);
    int unit = luaL_optint(L, 3, TUNTAP_ID_ANY);

    int ret = tuntap_start(ltuntap, mode, unit);
    if (ret==-1) return ltuntap_pushresult(L, ret);

    lua_pushinteger(L, ret);
    return 1;
}

static int ltuntap_up(lua_State* L)
{
    tuntap_t* ltuntap = CHECK_TUNTAP(1);

    int ret = tuntap_up(ltuntap);
    if (ret==-1) return ltuntap_pushresult(L, ret);

    lua_pushinteger(L, ret);
    return 1;
}

static int ltuntap_down(lua_State* L)
{
    tuntap_t* ltuntap = CHECK_TUNTAP(1);

    int ret = tuntap_down(ltuntap);
    if (ret==-1) return ltuntap_pushresult(L, ret);

    lua_pushinteger(L, ret);
    return 1;
}

static int ltuntap_get(lua_State* L)
{
    tuntap_t* ltuntap = CHECK_TUNTAP(1);
    const char* key = luaL_checkstring(L, 2);

    if (strcmp(key, "ifname") == 0) {
        lua_pushstring(L, tuntap_get_ifname(ltuntap));
    } else if (strcmp(key, "hwaddr") == 0) {
        lua_pushstring(L, tuntap_get_hwaddr(ltuntap));
    } else if (strcmp(key, "descr") == 0) {
        lua_pushstring(L, tuntap_get_descr(ltuntap));
    } else if (strcmp(key, "mtu") == 0) {
        lua_pushinteger(L, tuntap_get_mtu(ltuntap));
    } else if (strcmp(key, "fd") == 0) {
        lua_pushinteger(L, tuntap_get_fd(ltuntap));
    } else if (strcmp(key, "readable") == 0) {
        lua_pushinteger(L, tuntap_get_readable(ltuntap));
    } else {
        lua_pushnil(L);
    }
    return 1;
}

static int ltuntap_set(lua_State* L)
{
    tuntap_t* ltuntap = CHECK_TUNTAP(1);
    const char* key = luaL_checkstring(L, 2);
    const char* val = NULL;
    int i = -1;

    errno = 0;

    if (strcmp(key, "ifname") == 0) {
        val = luaL_checkstring(L, 3);
        i = tuntap_set_ifname(ltuntap, val);
    } else if (strcmp(key, "hwaddr") == 0) {
        val = luaL_checkstring(L, 3);
        i = tuntap_set_hwaddr(ltuntap, val);
    } else if (strcmp(key, "descr") == 0) {
        val = luaL_checkstring(L, 3);
        i = tuntap_set_descr(ltuntap, val);
    } else if (strcmp(key, "mtu") == 0) {
        i = luaL_checkint(L, 3);
        i = tuntap_set_mtu(ltuntap, i);
    } else if (strcmp(key, "nonblocking") == 0) {
        i = lua_toboolean(L, 3);
        i = tuntap_set_nonblocking(ltuntap, i);
    } else if (strcmp(key, "debug") == 0) {
        i = luaL_checkint(L, 3);
        i = tuntap_set_debug(ltuntap, i);
    } else if (strcmp(key, "ip") == 0) {
        val = luaL_checkstring(L, 3);
        i = luaL_checkint(L, 4);
        /* set ipaddr and netmask */
        i = tuntap_set_ip(ltuntap, val, i);
    } else if (strcmp(key, "dstip") == 0) {
        val = luaL_checkstring(L, 3);
        i = tuntap_set_dstip(ltuntap, val);
    }

    if (i==-1) return ltuntap_pushresult(L, i);

    lua_pushinteger(L, i);
    return 1;
}

static int ltuntap_tostring(lua_State* L)
{
    tuntap_t* ltuntap = CHECK_TUNTAP(1);
    lua_pushfstring(L, "%s: %p", TUNTAP_TNAME, ltuntap);
    return 1;
}

static const luaL_Reg ltuntap_meth[] = {
    {"destroy",   ltuntap_destroy},
    {"release",   ltuntap_release},

    {"start",     ltuntap_start},
    {"up",        ltuntap_up},
    {"down",      ltuntap_down},

    {"read",      ltuntap_read},
    {"write",     ltuntap_write},

    {"get",       ltuntap_get},
    {"set",       ltuntap_set},

    {NULL,        NULL}
};

static int ltuntap_version(lua_State* L)
{
    lua_pushinteger(L, tuntap_version());
    return 1;
}

static int ltuntap_new(lua_State* L)
{
    tuntap_t* ltuntap = tuntap_init();

    *(tuntap_t**)lua_newuserdata(L, sizeof(tuntap_t*)) = ltuntap;
    luaL_setmetatable(L, TUNTAP_TNAME);

    return 1;
}

static lua_State* _GL = NULL;
static void ltuntap_log(int level, const char *msg) {
    lua_State *L = _GL;
    if (L == NULL)
        return;

    lua_pushlightuserdata(L, ltuntap_log);
    lua_rawget(L, LUA_REGISTRYINDEX);
    if (lua_isfunction(L, -1))
    {
        lua_pushinteger(L, level);
        lua_pushstring(L, msg);

        if( lua_pcall(L, 2, 0, 0) == LUA_OK )
            return;
        lua_error(L);
    }
    lua_pop(L, 1);
}

static int ltuntap_log_set(lua_State *L)
{
    int type = lua_type(L, 1);
    if ( type == LUA_TFUNCTION )
    {
        lua_pushlightuserdata(L, ltuntap_log);
        lua_pushvalue(L, 1);
        lua_rawset(L, LUA_REGISTRYINDEX);
        _GL = L;
        tuntap_log_set_cb(ltuntap_log);
    } else if(type == LUA_TNONE || type == LUA_TNIL)
    {
        _GL = NULL;
        tuntap_log_set_cb(NULL);
    }else
        luaL_error(L, "only accpet a function or nil value to set or remove log callback");

    return 0;
}


static const luaL_Reg ltunlib[] = {
    {"version",   ltuntap_version},
    {"new",       ltuntap_new},
    {"log_set",   ltuntap_log_set},

    {"destroy",   ltuntap_destroy},
    {"release",   ltuntap_release},

    {"start",     ltuntap_start},
    {"up",        ltuntap_up},
    {"down",      ltuntap_down},

    {"read",      ltuntap_read},
    {"write",     ltuntap_write},

    {"get",       ltuntap_get},
    {"set",       ltuntap_set},

    {NULL,        NULL}
};

LUA_API int luaopen_ltuntap(lua_State* L)
{
    luaL_newlib(L, ltunlib);

#define PUSH_ENUM(x)                \
    lua_pushstring(L, #x);          \
    lua_pushinteger(L, TUNTAP_##x); \
    lua_rawset(L, -3)

    PUSH_ENUM(ID_MAX);
    PUSH_ENUM(ID_ANY);
    PUSH_ENUM(MODE_ETHERNET);
    PUSH_ENUM(MODE_TUNNEL);
    PUSH_ENUM(MODE_PERSIST);
    PUSH_ENUM(LOG_NONE);
    PUSH_ENUM(LOG_DEBUG);
    PUSH_ENUM(LOG_INFO);
    PUSH_ENUM(LOG_NOTICE);
    PUSH_ENUM(LOG_WARN);
    PUSH_ENUM(LOG_ERR);

#undef PUSH_ENUM

    lua_pushstring(L, "_VERSION");
    lua_pushfstring(L, "%d.%d", TUNTAP_VERSION_MAJOR, TUNTAP_VERSION_MINOR);
    lua_rawset(L, -3);

    luaL_newmetatable(L, TUNTAP_TNAME);
    lua_pushliteral(L, "__tostring");
    lua_pushcfunction(L, ltuntap_tostring);
    lua_rawset(L, -3);

    lua_pushliteral(L, "__gc");
    lua_pushcfunction(L, ltuntap_destroy);
    lua_rawset(L, -3);

    lua_pushliteral(L, "__index");
    lua_newtable(L);
    luaL_setfuncs(L, ltuntap_meth, 0);
    lua_rawset(L, -3);
    lua_pop(L, 1);

    return 1;
}

