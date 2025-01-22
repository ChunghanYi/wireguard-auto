/*
 * Configuration file client.conf
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <fstream>
#include <iostream>
#include <stdexcept>
#include "inc/configuration.h"
#include "spdlog/spdlog.h"

/*
 * Parse the client.conf file
 *	key1=value1
 *	key2=value2
 *	...
 *	keyN=valueN
 */
void Config::parse(const std::string& path) {
	std::ifstream openFile(path);

	if (openFile.is_open()) {
		std::string line;
		while (getline(openFile, line)) {
			std::string delimiter = " = ";
			if (std::string::npos == line.find(delimiter)) {
				delimiter = "=";
			}
			std::string key = line.substr(0, line.find(delimiter));
			if (key[0] == '#' || key[0] == ' ' || key[0] == '\0' ||
					key[0] == '\t' || key[0] == '\r' || key[0] == '\n') {
				continue;
			}
			spdlog::debug("### key ==> {}", key);
			std::string value = line.substr(
					line.find(delimiter) + delimiter.length(), line.length()
					);
			spdlog::debug("### value ==> {}", value);
			_config_tbl[key] = value;
		}
		openFile.close();
	}
}

/*
 * Check whether the value for the key is existent or not.
 */
bool Config::contains(const std::string& key) {
	if (_config_tbl.find(key) == _config_tbl.end()) {
		return false;
	} else {
		return true;
	}
}

/*
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

/*
 * Get the integer value for the key.
 */
int Config::getint(const std::string& key) {
	if (contains(key)) {
		return std::stoi(_config_tbl[key]);
	} else {
		throw std::invalid_argument("No value corresponding to the key.");
	}
}

/*
 * Get the floating point value for the key.
 */
float Config::getfloat(const std::string& key) {
	if (contains(key)) {
		return std::stof(_config_tbl[key]);
	} else {
		throw std::invalid_argument("No value corresponding to the key.");
	}
}

/*
 * Get the string value for the key.
 */
std::string Config::getstr(const std::string& key) {
	if (contains(key)) {
		if (_config_tbl[key].find("\"") == std::string::npos) {
			return _config_tbl[key];
		} else {
			return _config_tbl[key].substr(1, _config_tbl[key].length() - 2);
		}
	} else {
		throw std::invalid_argument("No value corresponding to the key.");
	}
}

/*
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
