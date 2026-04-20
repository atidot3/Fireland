#pragma once

#include <Utils/Asio/Describe.hpp>

struct characters
{
	uint32_t guid;
	uint32_t account;
	std::string name;
	uint8_t race;
	uint8_t char_class;
	uint8_t gender;
	uint8_t skin;
	uint8_t face;
	uint8_t hairStyle;
	uint8_t hairColor;
	uint8_t facialHair;
	uint8_t level;
	uint16_t zoneId;
	uint16_t mapId;
	float x;
	float y;
	float z;
	uint32_t guildId;
	uint32_t characterFlags;
	uint32_t customizationFlags;
	bool firstLogin;
};
BOOST_DESCRIBE_STRUCT(characters, (), (guid, account, name, race, char_class, gender, skin, face, hairStyle, hairColor, facialHair, level, zoneId, mapId, x, y, z, guildId, characterFlags, customizationFlags, firstLogin))
