/*
 * Startup Codes for WireGuard AutoConnect Client
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <signal.h>
#include "inc/client.h"
#include "inc/configuration.h"
#include "inc/sodium_aead.h"
#include "spdlog/spdlog.h"
#include <boost/program_options.hpp>

WgacClient wgacc;
const std::string versionString { "v0.3.00" };
std::string server_ip;

void sig_exit(int s) {
	wgacc.send_bye_message();
	sleep(1);

	spdlog::info("Closing wg_autoc...");
	pipe_ret_t finishRet = wgacc.close();
	if (finishRet.isSuccessful()) {
		spdlog::info("Client closed.");
	} else {
		spdlog::error("Failed to close wg_autoc.");
	}
	exit(EXIT_SUCCESS);
}

int do_fork() {
	int status = 0;

	switch (fork()) {
		case 0:
			// It's child
			break;
		case -1:
			/* fork failed */
			status = -1;
			break;
		default:
			// We should close master process with _exit(0)
			// We should not call exit() because it will destroy all global variables for program
			_exit(0);
	}

	return status;
}

void redirect_fds() {
	// Close stdin, stdout and stderr
	close(0);
	close(1);
	close(2);

	if (open("/dev/null", O_RDWR) != 0) {
		// We can't notify anybody now
		exit(1);
	}

	// Create copy of zero decriptor for 1 and 2 fd's
	// We do not need return codes here but we need do it for suppressing
	// complaints from compiler
	// Ignore warning because I prefer to have these unusued variables here for clarity
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
	int first_dup_result  = dup(0);
	int second_dup_result = dup(0);
#pragma GCC diagnostic pop
}

int main(int argc, char* argv[]) {
	bool daemonize = false;
	namespace po = boost::program_options;

	try {
		po::options_description desc("Allowed options");
		desc.add_options()
			("help", "Print help message")
			("version", "Show version")
			("daemon", "Detach from the terminal(run it in background)")
			("foreground", "Run it in foreground")
			("server", po::value<std::string>(),"Specify the server ip address")
			("config", po::value<std::string>(),"Set path to custom configuration file");

		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);

		if (vm.count("help")) {
			std::cout << desc << std::endl;
			exit(EXIT_SUCCESS);
		}

		if (vm.count("version")) {
			std::cout << "wg_autoc Version: " << versionString << "\n";
			std::cout << "Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>" << "\n";
			exit(EXIT_SUCCESS);
		}

		if (vm.count("daemon")) {
			daemonize = true;
		}

		if (vm.count("server")) {
			server_ip = vm["server"].as<std::string>();
		} else {
			spdlog::error("Server ip addres is not specified.");
			return EXIT_FAILURE;
		}

		if (vm.count("config")) {
			wgacc.getConf().parse(vm["config"].as<std::string>());
		} else {
			spdlog::error("Configuration file is not specified.");
			return EXIT_FAILURE;
		}
	} catch (po::error& e) {
		std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
		exit(EXIT_FAILURE);
	}

	if (daemonize) {
		int status = 0;

		std::cout << "We will run in daemonized mode" << std::endl;

		if ((status = do_fork()) < 0) {
			// fork failed
			status = -1;
		} else if (setsid() < 0) {
			// Create new session
			status = -1;
		} else if ((status = do_fork()) < 0) {
			status = -1;
		} else {
			// Clear inherited umask
			umask(0);

			// Chdir to root
			// I prefer to keep this variable for clarity
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
			int chdir_result = chdir("/");
#pragma GCC diagnostic pop

			// close all descriptors because we are daemon!
			redirect_fds();
		}
	}

	::signal(SIGINT, sig_exit);
	::signal(SIGQUIT, sig_exit);
	::signal(SIGTERM, sig_exit);

	sodium_aead::initialize_sodium();

	// connect client to an open server
	bool connected = false;
	while (!connected) {
		pipe_ret_t connectRet = wgacc.connectTo(server_ip, 51822);
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
	wgacc.start();

	return 0;
}
