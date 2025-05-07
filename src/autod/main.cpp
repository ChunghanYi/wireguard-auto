/*
 * Startup Codes for WireGuard AutoConnect Server
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <signal.h>
#include <vector>
#include "inc/server.h"
#include "inc/common.h"
#include "inc/vtysh.h"
#include "inc/configuration.h"
#include "spdlog/spdlog.h"
#include <boost/program_options.hpp>

WgacServer wg_autod;
const std::string versionString { "v0.2.00" }; 

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

void acceptClients() {
	try {
		std::string clientIP = wg_autod.acceptClient(0);
	} catch (const std::runtime_error &error) {
		spdlog::error("Accepting client failed: {}", error.what());
	}
}

int main(int argc, char** argv) {
	bool daemonize = false;
	namespace po = boost::program_options;

	try {
		po::options_description desc("Allowed options");
		desc.add_options()
			("help", "Print help message")
			("version", "Show version")
			("daemon", "Detach from the terminal(run it in background)")
			("foreground", "Run it in foreground")
			("config", po::value<std::string>(),"Set path to custom configuration file");

		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);

		if (vm.count("help")) {
			std::cout << desc << std::endl;
			exit(EXIT_SUCCESS);
		}

		if (vm.count("version")) {
			std::cout << "wg_autod Version: " << versionString << std::endl;
			std::cout << "Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>" << "\n";
			exit(EXIT_SUCCESS);
		}

		if (vm.count("daemon")) {
			daemonize = true;
		}

		if (vm.count("config")) {
			if (wg_autod.getConf().parse(vm["config"].as<std::string>()) == false) {
				return EXIT_FAILURE;
			}
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

	::signal(SIGINT, sig_handler);
	::signal(SIGQUIT, sig_handler);
	::signal(SIGTERM, sig_handler);

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
