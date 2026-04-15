/*
 * Startup Codes for WireGuard AutoConnect Client
 * Copyright (c) 2025-2026 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <signal.h>
#include "inc/client.h"
#include "inc/configuration.h"
#include "inc/sodium_ae.h"
#include "spdlog/spdlog.h"
#include <boost/program_options.hpp>

////////////////////////////////////////////////////////////
std::unique_ptr<WgacClient> wgaccPtr;
const std::string prog_name { "wg_autoc" };
const std::string versionString { "v0.8.50" };
////////////////////////////////////////////////////////////

static void sig_exit(int s) {
	wgaccPtr->send_bye_message();
	sleep(1);

	spdlog::info("Closing {}...", prog_name);
	pipe_ret_t finishRet = wgaccPtr->close();
	if (finishRet.isSuccessful()) {
		spdlog::info("--- Client closed.");
	} else {
		spdlog::error("Failed to close {}.", prog_name);
	}
	std::_Exit(EXIT_SUCCESS);
}

auto last_processed = std::chrono::steady_clock::now();
const auto interval = std::chrono::milliseconds(1000);

static void sig_usr1(int s) {
	auto now = std::chrono::steady_clock::now();
	if (now - last_processed <= interval) {
		last_processed = now;
		std::cout << "Too fast SIGUSR1 signal is ignored.\n";
		return;
	}

	last_processed = now;

	if (!wgaccPtr->isConnected() || wgaccPtr->isWireguardReady()) {
		wgaccPtr->setRestart(true);
	} else {
		std::cout << "SIGUSR1 signal is ignored.\n";
	}
}

static int do_fork() {
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

static void redirect_fds() {
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
	unsigned short wgac_server_port {51822};

	//Creates a smart pointer for an instance of the client class.
	wgaccPtr = std::make_unique<WgacClient>();
	if (wgaccPtr == nullptr) {
		spdlog::error("Failed to create a smart pointer for WgacClient class.");
		return EXIT_FAILURE;
	}

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
			std::cout << prog_name << " Version: " << versionString << "\n";
			std::cout << "Copyright (c) 2025-2026 Slowboot <chunghan.yi@gmail.com>" << "\n";
			exit(EXIT_SUCCESS);
		}

		if (vm.count("daemon")) {
			daemonize = true;
		}

		if (vm.count("server")) {
			wgaccPtr->setServerIp(vm["server"].as<std::string>());
		} else {
			spdlog::error("Server ip addres is not specified.");
			return EXIT_FAILURE;
		}

		if (vm.count("config")) {
			wgaccPtr->getConfig().parse(vm["config"].as<std::string>());
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
	::signal(SIGUSR1, sig_usr1);

	// Initialize libsodium
	sodium_ae::initialize_sodium();

	// Initialize curve25519 keypair(private/public keys)
	char pubkey_base64[WG_KEY_LEN_BASE64] = {};
	char privkey_base64[WG_KEY_LEN_BASE64] = {};
	if (!initialize_curve25519(pubkey_base64, privkey_base64)) {
		spdlog::warn("Failed to get curve25519 keypair.");
	} else {
		spdlog::debug("WireGuard public key => {}", pubkey_base64);
		std::string s(pubkey_base64);
		wgaccPtr->getConfig().setstr("this_public_key", s);

		uint8_t key[WG_KEY_LEN];
		if (!key_from_base64(key, privkey_base64)) {
			spdlog::warn("Private key is not the correct length or format");
			return EXIT_FAILURE;
		}
		wgaccPtr->setPrepareSecretKey(key);
	}

	while (1) {
		// connect client to an wireguard auto connection server
		bool connected = false;
		while (!connected) {
			if (wgaccPtr->getConfig().getint("server_port") >= 1024 &&
					wgaccPtr->getConfig().getint("server_port") < 65536) {
				wgac_server_port = wgaccPtr->getConfig().getint("server_port");
			}
			pipe_ret_t connectRet = wgaccPtr->connectTo(wgaccPtr->getServerIp(), wgac_server_port);
			connected = connectRet.isSuccessful();
			if (connected) {
				spdlog::info("--- Client connected successfully");
			} else {
				spdlog::info("--- Client failed to connect: {}", connectRet.message());
				sleep(2);
				spdlog::info("--- Retrying to connect...");
			}
		};

		// start PING-PONG protocol(core routine)
		wgaccPtr->start();

		// Wait until a restart request is coming
		while (!wgaccPtr->shouldRestart()) {
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
		wgaccPtr->setRestart(false);

		if (wgaccPtr->isClosed()) {
			spdlog::info("--- Client is already closed");
			std::this_thread::sleep_for(std::chrono::seconds(2));
			spdlog::info("--- OK, Let's reconnect to the AutoConnect server.");
		} else {
			wgaccPtr->send_bye_message();
			std::this_thread::sleep_for(std::chrono::seconds(1));
			pipe_ret_t finishRet = wgaccPtr->close();
			if (finishRet.isSuccessful()) {
				spdlog::info("--- Client is closed");
				std::this_thread::sleep_for(std::chrono::seconds(2));
				spdlog::info("--- OK, Let's reconnect to the AutoConnect server.");
			} else {
				spdlog::error("Client connection closing is failed.");
				break;
			}
		}
	}

	return 0;
}
