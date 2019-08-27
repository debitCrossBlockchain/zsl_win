#include "NoteEncryption.h"
#include "common.h"
#include <fstream>
#include <sstream>
#include <string>
#include<iostream>
#include <random>
using namespace std;
NoteEncryption::NoteEncryption(){
	unsigned char pk[32];
	unsigned char sk[32];
	GetKeypair(sk,pk);
	esk_ = ArrayToHexString(sk, 32);
	epk_ = ArrayToHexString(pk, 32);
	GetRandomness(erho_, 32);
}

void NoteEncryption::GetRandomness(std::string& output, int64_t len){
	char* buf = new char[len];
#ifdef  WIN32
	/*std::random_device rd;
	for (int i = 0; i < len; i++) {
		buf[i] = (uint8_t)std::uniform_int_distribution<uint16_t>(0, 255)(rd);
	}*/
	randombytes_buf(buf, len);
	output = BinToHexString(buf, len);
#else
	std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
	if (urandom) {
		urandom.read(buf, len);
		if (urandom) {
			output = BinToHexString(buf, len);
		}
		urandom.close();
	}
#endif //  WIN32
}
void NoteEncryption::GetRandomness(unsigned char* output, int64_t len){
	std::string hex;
	GetRandomness(hex, len);
	HexStringToArray(hex, output);
}

std::string NoteEncryption::GetErho(){
	return erho_;
}

void NoteEncryption::GetKeypair(unsigned char* priv, unsigned char* pub){
	GetRandomness(priv, 32);
	sha256(priv, 32, pub);
}