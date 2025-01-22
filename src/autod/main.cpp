/*
 * Startup Codes for WireGuard AutoConnect Server
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <csignal>
#include <vector>
#include "inc/server.h"
#include "inc/common.h"
#include "inc/vtysh.h"
#include "inc/configuration.h"
#include "spdlog/spdlog.h"

WacServer wg_autod;
const std::string versionString { "v0.1.99" }; 

static void printUsage() {
	std::cout << "Usage: wg_autod [OPTION] <config-file-path>" << "\n";
	std::cout << "Options" << "\n";
	std::cout << " -f, --foreground    in foreground" << "\n";
	std::cout << " -d, --daemon        fork in background" << "\n";
	std::cout << " -v, --version       show version information and exit" << "\n\n";
	exit(EXIT_FAILURE);
}

static void printVersion() {
	std::cout << "wg_autod " << versionString << "\n";
	std::cout << "Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>" << "\n";
	exit(EXIT_SUCCESS);
}

static void sig_handler(int sig) {
	switch (sig) {
		case SIGINT:
		case SIGTERM:
		case SIGQUIT:
			spdlog::info(">>> Received signal {}, exiting...", sig);
			wg_autod.setTerminate(true);
			wg_autod.close();
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
	}
}

static void daemonize(void) {
	int r;

	r = daemon(0, 0);
	if (r != 0) {
		spdlog::info("Unable to daemonize");
		exit(EXIT_FAILURE);
	}
}

constexpr unsigned int hashMagic(const char *str) {
	return str[0] ? static_cast<unsigned int>(str[0]) + 0xEDB8832Full * hashMagic(str + 1) : 8603;
}

void acceptClients() {
	try {
		std::string clientIP = wg_autod.acceptClient(0);
	} catch (const std::runtime_error &error) {
		spdlog::error("Accepting client failed: {}", error.what());
	}
}

int main(int argc, char** argv) {
	if (argc != 3) {
		printUsage();
	}

	switch (hashMagic(argv[1])) {
		case hashMagic("-v"):
		case hashMagic("--version"):
			printVersion();
			break;

		case hashMagic("-f"):
		case hashMagic("--foreground"):
			break;

		case hashMagic("-d"):
		case hashMagic("--daemon"):
			daemonize();
			break;

		default:
			printUsage();
			break;
	}

	if (argv[2]) {
		wg_autod.getConf().parse(argv[2]);
	} else {
		spdlog::error("Configuration file is not specified.");
		return EXIT_FAILURE;
	}

	signal(SIGINT, sig_handler);
	signal(SIGQUIT, sig_handler);
	signal(SIGTERM, sig_handler);

	spdlog::info("Starting the wg_autod(tcp port 51822)...");
	vtyshell::initializeVtyshMap();
	pipe_ret_t startRet = wg_autod.start(51822);
	if (!startRet.isSuccessful()) {
		spdlog::error("Server setup failed: {}", startRet.message());
		return EXIT_FAILURE;
	}

	while (!wg_autod.shouldTerminate()) {
		acceptClients();
	}

	wg_autod.close();
	spdlog::info("The wg_autod is stopped.");

	return EXIT_SUCCESS;
}
