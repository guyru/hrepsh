/*
 * hrepsh - 
 * Copyright (C) 2013-2014 Guy Rutenberg
 * http://www.guyrutenberg.com
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <error.h>

#include <boost/format.hpp>
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/cryptlib.h>
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include <cryptopp/filters.h>
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::HashFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include <cryptopp/files.h>
using CryptoPP::FileSource;

#include <cryptopp/hmac.h>
using CryptoPP::HMAC;

#include <cryptopp/sha.h>
using CryptoPP::SHA256;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "config.h"

using namespace std;

#define IV_SIZE AES::BLOCKSIZE
#define KEY_SIZE (256 / 8)

enum { // Return codes
	INVALID_INPUT = 2,
	IO_ERROR,
};

/**
 * Get the path to the executable of the parent process.
 */
string get_parent_process_path()
{
	pid_t ppid = getppid();
	boost::format proc_path("/proc/%d/exe");
	char *path = realpath(boost::str(proc_path % ppid).c_str(), NULL);
	if (!path) {
		error(1, errno, NULL);
	}
	string  parent_path(path);
	free(path);
	return parent_path;
}

/**
 * Get the parent process' command line.
 */
vector<string> get_parent_process_cmdline()
{
	pid_t ppid = getppid();
	boost::format proc_path("/proc/%d/cmdline");
	fstream cmdline_file(boost::str(proc_path % ppid), ios::binary | ios::in);
	vector<string> arguments;

	for (string argument; getline(cmdline_file, argument, '\0');) {
		arguments.push_back(argument);
	}

	return arguments;
}


/**
 * Returns the secret key from the configuration file.
 */
vector<byte> get_secret_key()
{
	vector<byte> secret_key(KEY_SIZE);
	fstream sec_file(SECRET_FILE, ios::binary | ios::in);
	if (!sec_file) {
		exit(IO_ERROR);
	}
	sec_file.read((char *) secret_key.data(), secret_key.size());
	if (!sec_file.good() || sec_file.gcount() != secret_key.size()) {
		exit(IO_ERROR);
	}
	return secret_key;
}


string get_key(string parent_path)
{
	vector<byte> secret_key = get_secret_key();
	uid_t user = getuid();
	string salt = (std::to_string(user) +
		string("\x00", 1) +
		parent_path);
	string final_key;

	try {
		HMAC< SHA256 > hmac(secret_key.data(), secret_key.size());

		StringSource(salt, true,
				new HashFilter(hmac,
					new StringSink(final_key)
					) // HashFilter
			    ); // StringSource
	} catch(const CryptoPP::Exception& e) {
		cerr << e.what() << endl;
		exit(1);
	}

	return final_key;
}

/**
 * Get the derived key for an interpreted program.
 */
string get_key_interpreted(string interpreter, string script_name)
{
	vector<byte> secret_key = get_secret_key();
	uid_t user = getuid();
	string salt = (std::to_string(user) +
		string("\x00", 1) +
		interpreter +
		string("\x00", 1) +
		script_name);
	string final_key;

	try {
		HMAC< SHA256 > hmac(secret_key.data(), secret_key.size());

		StringSource(salt, true,
				new HashFilter(hmac,
					new StringSink(final_key)
					) // HashFilter
			    ); // StringSource
	} catch(const CryptoPP::Exception& e) {
		cerr << e.what() << endl;
		exit(1);
	}

	return final_key;
}

string encrypt_stdin(string parent_path, string interpreter)
{
	string output;
	string key;

	if (interpreter.size()) {
		key = get_key_interpreted(interpreter, parent_path);
	} else {
		key = get_key(parent_path);
	}

	AutoSeededRandomPool prng;
	byte iv[ IV_SIZE ];
	prng.GenerateBlock( iv, sizeof(iv) );
	output = string(reinterpret_cast<char *>(iv), sizeof(iv));

	GCM<AES>::Encryption e;
	e.SetKeyWithIV((const byte*)key.data(), key.size(), iv, sizeof(iv));

	FileSource( cin, true,
		new AuthenticatedEncryptionFilter( e,
			new StringSink( output )
			) // AuthenticatedEncryptionFilter
		); // StringSource
	return output;
}

string decrypt_stdin(string interpreter)
{
	string output;
	string key;

	if (interpreter.size()) {
		auto cmd_line = get_parent_process_cmdline();
		if (cmd_line.size() < 2) {
			exit(INVALID_INPUT);
		}

		string script_name = cmd_line[1];
		key = get_key_interpreted(interpreter, script_name);
	} else {
		key = get_key(get_parent_process_path());
	}

	byte iv[ AES::BLOCKSIZE ];
	cin.read(reinterpret_cast<char *>(iv), sizeof(iv));
	if (!cin) {
		exit(INVALID_INPUT);
	}
	GCM< AES >::Decryption d;
	d.SetKeyWithIV( (const byte*)key.data(), key.size(), iv, sizeof(iv) );

	try {
		AuthenticatedDecryptionFilter df( d,
				new StringSink( output ),
				AuthenticatedDecryptionFilter::DEFAULT_FLAGS
				); // AuthenticatedDecryptionFilter

		// The StringSource dtor will be called immediately
		//  after construction below. This will cause the
		//  destruction of objects it owns. To stop the
		//  behavior so we can get the decoding result from
		//  the DecryptionFilter, we must use a redirector
		//  or manually Put(...) into the filter without
		//  using a StringSource.
		FileSource ( cin, true,
				new Redirector( df /*, PASS_EVERYTHING */ )
			    ); // StringSource

		// If the object does not throw, here's the only
		//  opportunity to check the data's integrity
		bool b = df.GetLastResult();
		assert( true == b );
	} catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e ) {
		cerr << "Caught HashVerificationFailed..." << endl;
		cerr << e.what() << endl;
		cerr << endl;
		exit(INVALID_INPUT);
	} catch( CryptoPP::InvalidArgument& e ) {
		cerr << "Caught InvalidArgument..." << endl;
		cerr << e.what() << endl;
		cerr << endl;
		exit(INVALID_INPUT);
	} catch( CryptoPP::Exception& e ) {
		cerr << "Caught Exception..." << endl;
		cerr << e.what() << endl;
		cerr << endl;
		exit(INVALID_INPUT);
	}

	return output;
}

int main(int argc, char **argv)
{
	string parent_path;
	string interpreter;
	po::options_description desc("Options");
        desc.add_options()
		("help,h", "display this help message and exit")
		("version", "output version information and exit")
		("encrypt,e", po::value<string>(&parent_path),
			"encrypt the input for the specified program.")
		("interpreter,i", po::value<string>(&interpreter)->implicit_value(""),
			"When decrypting the input, assume that the process is "
			"executed via interpreter. If encrypting data for a "
			"interpreted program, use this option to specify which"
			"interpreter is used.")
        ;

	po::variables_map vm;
	try {
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
	} catch ( const po::error& e ) {
		cerr << PACKAGE ": " << e.what() << endl;
		cerr << "Try `" PACKAGE " --help' for more information. "
			<< endl;
		return 1;
	}

	if (vm.count("help")) {
		cout << "Synopsis:" << endl;
		cout << "  " PACKAGE " [options]" << endl << endl;
		cout << desc << endl;
		return 0;
	}
	if (vm.count("version")) {
		cout << PACKAGE_STRING << endl;
		cout << "Copyright (C) 2013-2014 Guy Rutenberg " << endl;
		return 0;
	}

	string output;
	if (vm.count("encrypt")) {
		if (vm.count("interpreter") && interpreter.size() == 0) {
			interpreter = get_parent_process_path();
		}
		output = encrypt_stdin(parent_path, interpreter);
	} else { // decrypt whatever on stdin
		if (vm.count("interpreter") && interpreter.size() == 0) {
			interpreter = get_parent_process_path();
		}
		output = decrypt_stdin(interpreter);
	}

	cout << output ;
	return 0;
}
