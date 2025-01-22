/*
 * Startup Codes for WireGuard AutoConnect Client
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <csignal>
#include "inc/client.h"
#include "inc/configuration.h"
#include "spdlog/spdlog.h"

WacClient wg_autoc;

const std::string versionString { "v0.1.99" };

static void printUsage() {
	std::cout << "Usage: wg_autoc [OPTION] <server-ip> <config-file-path>" << "\n";
	std::cout << "Options" << "\n";
	std::cout << " -f, --foreground    in foreground" << "\n";
	std::cout << " -d, --daemon        fork in background" << "\n";
	std::cout << " -v, --version       show version information and exit" << "\n\n";
	exit(EXIT_FAILURE);
}

static void printVersion() {
	std::cout << "wg_autoc " << versionString << "\n";
	std::cout << "Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>" << "\n";
	exit(EXIT_SUCCESS);
}

void sig_exit(int s) {
	wg_autoc.send_bye_message();
	sleep(1);

	spdlog::info("Closing wg_autoc...");
	pipe_ret_t finishRet = wg_autoc.close();
	if (finishRet.isSuccessful()) {
		spdlog::info("Client closed.");
	} else {
		spdlog::error("Failed to close wg_autoc.");
	}
	exit(EXIT_SUCCESS);
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

int main(int argc, char **argv) {
	if (argc != 4) {
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

	if (argv[3]) {
		wg_autoc.getConf().parse(argv[3]);
	} else {
		spdlog::error("Configuration file is not specified.");
		return EXIT_FAILURE;
	}

	signal(SIGINT, sig_exit);
	signal(SIGQUIT, sig_exit);
	signal(SIGTERM, sig_exit);

	// connect client to an open server
	bool connected = false;
    while (!connected) {
        pipe_ret_t connectRet = wg_autoc.connectTo(argv[2], 51822);
        connected = connectRet.isSuccessful();
        if (connected) {
			spdlog::info("Client connected successfully");
        } else {
			spdlog::info("Client failed to connect: {}", connectRet.message());
            sleep(2);
			spdlog::info("Retrying to connect...");
        }
	};

	// main: PING-PONG protocol
	wg_autoc.start_wgauto_protocol();

	return 0;
}
