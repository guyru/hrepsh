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

string get_key(string parent_path)
{
	byte secret_key[KEY_SIZE]; // this should be replaced by something that will zero out the memory once destructed.
	fstream sec_file(SECRET_FILE, ios::binary | ios::in);
	if (!sec_file) {
		exit(IO_ERROR);
	}
	sec_file.read(reinterpret_cast<char *>(secret_key), sizeof(secret_key));
	if (!sec_file.good() || sec_file.gcount() != sizeof(secret_key)) {
		exit(IO_ERROR);
	}
	uid_t user = getuid();
	string salt = (std::to_string(user) +
		string("\x00", 1) + 
		parent_path);
	string final_key;

	try {
		HMAC< SHA256 > hmac(secret_key, sizeof(secret_key));

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


int main(int argc, char **argv)
{
	string file_name;
	po::options_description desc("Options");
        desc.add_options()
		("help,h", "display this help message and exit")
		("version", "output version information and exit")
		("encrypt,e", po::value<string>(&file_name),
			"encrypt the input for the specified program.")
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
		string key = get_key(file_name);
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
	} else { // decrypt whatever on stdin
		string key = get_key(get_parent_process_path());
		byte iv[ AES::BLOCKSIZE ];
		cin.read(reinterpret_cast<char *>(iv), sizeof(iv));
		if (!cin) {
			// couldn't 
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
	}

	cout << output ;
	return 0;
}
