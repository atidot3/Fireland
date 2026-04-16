#pragma once

#include <string>

// -- DATABASE
static const std::string DATABASE_HOST("database.Host");
static const std::string DATABASE_PORT("database.Port");
static const std::string DATABASE_USER("database.User");
static const std::string DATABASE_PASSWORD("database.Password");
static const std::string DATABASE_MAX_CONNECTION("database.MaxConnection");
static const std::string DATABASE_AUTH("database.AuthDB");
static const std::string DATABASE_CHAR("database.CharDB");
static const std::string DATABASE_GAME("database.WorldDB");

// -- SERVER
static const std::string SERVER_SERVER_IP("server.BindIP");
static const std::string SERVER_SERVER_PORT("server.BindPort");
static const std::string SERVER_SERVER_DATA("server.DataDir");
static const std::string SERVER_THREAD_COUNT("server.ThreadCount");

// -- GAME
static const std::string GAME_EXPANSION("game.Expansion");
static const std::string GAME_MAX_LEVEL("game.MaxLevel");