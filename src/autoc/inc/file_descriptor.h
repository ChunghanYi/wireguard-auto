#pragma once

class FileDescriptor {
public:
	void set(int fd) { _sockfd = fd; }
	int get() const { return _sockfd; }

private:
	int _sockfd = 0;
};
