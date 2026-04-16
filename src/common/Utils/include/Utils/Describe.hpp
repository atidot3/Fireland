#pragma once

#include <string_view>

#include <boost/core/demangle.hpp>
#include <boost/describe.hpp>
#include <boost/mp11.hpp>

namespace Fireland::Utils::Describe
{
	//FUNCTIONS USED WITH
	//BOOST_DESCRIBE_ENUM()
	//see https://www.boost.org/doc/libs/1_84_0/libs/describe/doc/html/describe.html#enums

	//--enums specifics--------------------

	template<typename Enum>
	concept enum_was_described = !boost::mp11::mp_empty<boost::describe::describe_enumerators<Enum>>::value;

	//enum value to string conversion
	template<class Enum>
	std::string_view to_string(Enum value) noexcept
	{
		static_assert(enum_was_described<Enum>, "this enum was not described with BOOST_DESCRIBE_ENUM/BOOST_DESCRIBE_NESTED_ENUM. "
			"See https://www.boost.org/doc/libs/1_85_0/libs/describe/doc/html/describe.html#enums for infos");

		std::string_view str = "(unknown)";
		boost::mp11::mp_for_each<boost::describe::describe_enumerators<Enum>>([&](auto desc) { if (value == desc.value) str = desc.name; });
		return str;
	}

	//string value to enum conversion
	template<typename Enum>
	Enum from_string(std::string_view name, Enum defaultValue) noexcept
	{
		static_assert(enum_was_described<Enum>, "this enum was not described with BOOST_DESCRIBE_ENUM/BOOST_DESCRIBE_NESTED_ENUM. "
			"See https://www.boost.org/doc/libs/develop/libs/describe/doc/html/describe.html#classes for infos");

		Enum value = std::move(defaultValue);
		boost::mp11::mp_for_each<boost::describe::describe_enumerators<Enum>>([&](auto desc) {
			if (name == desc.name) value = desc.value;
			});
		return value;
	}

	//--struct/class specifics-----------------

	template<typename T>
	using members = boost::describe::describe_members<T, boost::describe::mod_public>;

	template<typename T>
	concept object_was_described = !boost::mp11::mp_empty<members<T>>::value;


} // namespace utils
