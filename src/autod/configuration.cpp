/*
 * Configuration file server.conf
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <fstream>
#include <iostream>
#include <stdexcept>
#include "inc/configuration.h"
#include "spdlog/spdlog.h"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>

/**
 * Parse the server.conf file
 *	key1 = value1
 *	key2 = value2
 *	...
 *	keyN = valueN
 */
bool Config::parse(const std::string& path) {
	std::ifstream config_file(path);
	std::string line;

	if (!config_file.is_open()) {
		spdlog::error("Can't open config file");
		return false;
	}

	while (getline(config_file, line)) {
		std::vector<std::string> parsed_config;
		boost::algorithm::trim(line);

		if (line.find("#") == 0 or line.empty()) {
			// Ignore comments line
			continue;
		}

		boost::split(parsed_config, line, boost::is_any_of("="), boost::token_compress_on);

		if (parsed_config.size() == 2) {
			boost::algorithm::trim(parsed_config[0]);
			boost::algorithm::trim(parsed_config[1]);

#ifdef DEBUG
			spdlog::debug("### key   ==> {}", parsed_config[0]);
			spdlog::debug("### value ==> {}", parsed_config[1]);
#endif
			_config_tbl[parsed_config[0]] = parsed_config[1];
		} else if (parsed_config.size() == 3) {
			boost::algorithm::trim(parsed_config[0]);
			boost::algorithm::trim(parsed_config[1]);
			boost::algorithm::trim(parsed_config[2]);
			std::string value = parsed_config[1] + "=" + parsed_config[2];

#ifdef DEBUG
			spdlog::debug("### key   ==> {}", parsed_config[0]);
			spdlog::debug("### value ==> {}", value);
#endif
			_config_tbl[parsed_config[0]] = value;
		} else {
			spdlog::error("Can't parse config line: {}", line);
		}
	}
	config_file.close();

	return true;
}

/**
 * Check whether the value for the key is existent or not.
 */
bool Config::contains(const std::string& key) {
	if (_config_tbl.find(key) == _config_tbl.end()) {
		return false;
	} else {
		return true;
	}
}

/**
 * Get the boolean value for the key.
 */
bool Config::getbool(const std::string& key) {
	if (contains(key)) {
		if (_config_tbl[key] == "true" || _config_tbl[key] == "TRUE") {
			return true;
		} else {
			return false;
		}
	} else {
		throw std::invalid_argument("No value corresponding to the key.");
	}
}

/**
 * Get the integer value for the key.
 */
int Config::getint(const std::string& key) {
	if (contains(key)) {
		return std::stoi(_config_tbl[key]);
	} else {
		throw std::invalid_argument("No value corresponding to the key.");
	}
}

/**
 * Get the floating point value for the key.
 */
float Config::getfloat(const std::string& key) {
	if (contains(key)) {
		return std::stof(_config_tbl[key]);
	} else {
		throw std::invalid_argument("No value corresponding to the key.");
	}
}

/**
 * Get the string value for the key.
 */
std::string Config::getstr(const std::string& key) {
	if (contains(key)) {
		if (_config_tbl[key].find("\"") == std::string::npos) {
			return _config_tbl[key];
		} else {
#ifdef DEBUG
			spdlog::debug("### ({}) value ==> {}",
					__func__, _config_tbl[key].substr(1, _config_tbl[key].length() - 2));
#endif
			return _config_tbl[key].substr(1, _config_tbl[key].length() - 2);
		}
	} else {
		throw std::invalid_argument("No value corresponding to the key.");
	}
}

/**
 * Set the string value for the key.
 */
bool Config::setstr(const std::string& key, const std::string& value) {
	if (contains(key)) {
		_config_tbl[key] = value;
		return true;
	} else {
		return false;
	}
}
