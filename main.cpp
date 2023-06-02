// compile with: g++ socketexample.cpp -lwsock32
#define _CRT_SECURE_NO_WARNINGS	// ignore scanf warnings in visual studio
#define CESTA "D:\\hajny\\funkcni_cpp\\appsettings_o.json"
#define CESTAD "D:\\hajny\\funkcni_cpp\\appsettings.json"


#define NOMINMAX
#include <stdio.h>      // for printf
#include <winsock2.h>   // the networking library.
#include <Ws2tcpip.h>	// more tcp/ip functionality
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <vector>       // for the server's client list and input buffer
#include <conio.h>      // for kbhit() and getch()
#include <span>
#include "nlohmann/json.hpp"

using namespace nlohmann;
using namespace std;
#pragma comment(lib, "ws2_32.lib") // links WinSock2 with MS Visual Studio


#include <stdint.h>


int clientLogic(SOCKET srvSock, const sockaddr* connectionAddr);
const int STATUS_READ = 0x1, STATUS_WRITE = 0x2, STATUS_EXCEPT = 0x4; // used by getStatus
int getStatus(const SOCKET a_socket, int status);
int deaktivacesocketu(SOCKET socket);
void finalWSACleanup();




std::string jsonToString(std::string jsonFile)
{
	std::ifstream file(jsonFile);
	if (!file.is_open())
	{
		printf("Error opening file");

	}
	std::string str((std::istreambuf_iterator<char>(file)),
		std::istreambuf_iterator<char>());

	return str;
}

json stringToJson(std::string jsonString)
{
	json j = json::parse(jsonString);
	return j;
}

std::string hexToString(const char* hex, size_t len) {
	std::string str(len * 2, '0'); // create string with length equal to twice the length of the input
	for (size_t i = 0; i < len; ++i) {
		// convert each 4-bit nibble to a hex digit and append to string
		str[2 * i] = "0123456789abcdef"[(hex[i] >> 4) & 0xF];
		str[2 * i + 1] = "0123456789abcdef"[hex[i] & 0xF];
	}
	
	return str;
}

int processResponse(const std::string& response)
{
	// Check if the response is empty or has an odd number of characters
	if (response.length() == 0 || response.length() % 2 != 0) {
		return 0;
	}

	bool is01010000 = true; // assume the response is 01 01 00 00
	bool is01030051 = true; // assume the response is 01 03 00 51
	bool is01020000 = true; // assume the response is 01 02 00 00

	// Iterate over the response string two characters at a time to extract the bytes
	for (int i = 0; i < response.length(); i += 2) {
		// Check if the current two characters are valid hexadecimal digits
		if (!isxdigit(response[i]) || !isxdigit(response[i + 1])) {
			return 0;
		}
		// Convert the two hexadecimal characters to an integer byte value
		int byteValue = std::stoi(response.substr(i, 2), nullptr, 16);
		std::cout << std::hex << std::setfill('0') << std::setw(2) << byteValue << " ";
		if (is01010000 && (byteValue != 0x01 && byteValue != 0x00)) {
			// If the byte value does not match 01 or 00, the response is not 01 01 00 00
			is01010000 = false;
		}
		if (is01030051 && (byteValue != 0x01 && byteValue != 0x03 && byteValue != 0x00 && byteValue != 0x51)) {
			// If the byte value does not match 01 03 00 51, the response is not 01 03 00 51
			is01030051 = false;
		}
		if (is01020000 && (byteValue != 0x01 && byteValue != 0x02 && byteValue != 0x00)) {
			// If the byte value does not match 01 02 00 00, the response is not 01 02 00 00
			is01020000 = false;
		}
	}

	std::cout << "\n" << std::endl;

	if (is01010000) {
		return 1;
	}
	else if (is01030051) {
		return 3;
	}
	else if (is01020000) {
		return 2;
	}
	else {
		return 0;
	}
}

unsigned long howMuchInBufferdata = 0;
unsigned long numBytesReaddata = 0;

unsigned long howMuchInBufferend = 0;
unsigned long numBytesReadend = 0;

SOCKET endSock = 0;
SOCKET dataSock = 0;
SOCKET srvSock = 0;

int main()
{
	sockaddr_in connectionAddress;
	unsigned short myPort = 1337;
	int portInput;
	printf("what port? "); scanf_s("%i", &portInput);

	std::string jsons = jsonToString(CESTA).c_str();
	std::cout << "posilany config  " + jsons << std::endl;

	myPort = (short)portInput;
	memset(&connectionAddress, 0, sizeof(sockaddr_in)); // initialize to zero

	connectionAddress.sin_family = AF_INET;
	// big-endian 
	connectionAddress.sin_port = htons(myPort);

	// initialize 
	int result;
	WSADATA wsaData; // gets populated w/ info explaining this sockets implementation

	if ((result = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
	{
		printf("WSAStartup() error %d\n", result);
		return EXIT_FAILURE;
	}
	atexit(finalWSACleanup); // add callback to trigger when program ends. cleans up sockets
	// create the main socket, either client or server
	
	srvSock = socket(
		AF_INET,
		SOCK_STREAM,
		IPPROTO_TCP);
	
	if (srvSock == INVALID_SOCKET)
	{
		printf("socket() error %d\n", WSAGetLastError());
		return EXIT_FAILURE;
	}
	// 1 to set non-blocking, 0 to set re-usable
	unsigned long argp = 1;
	result = setsockopt(srvSock,
		SOL_SOCKET,
		SO_REUSEADDR, //znovupouziti adressy
		(char*)&argp, sizeof(argp));
	if (result != 0)
	{
		printf("setsockopt() error %d\n", result);
		return EXIT_FAILURE;
	}
	// 1 to set non-blocking, 0 to set blocking
	argp = 1;
	if (ioctlsocket(srvSock,
		FIONBIO,
		&argp) == SOCKET_ERROR)
	{
		printf("ioctlsocket() error %d\n", WSAGetLastError());
		return EXIT_FAILURE;
	}



	// connect to the server
	const char* targetIP = "127.0.0.1"; // "::1"; // IPv6 localhost doesn't appear to work...
	unsigned long raw_ip_nbo;// = inet_addr(targetIP); // inet_addr is an old method for IPv4
	inet_pton(AF_INET, targetIP, &raw_ip_nbo); // IPv6 method of address acquisition
	if (raw_ip_nbo == INADDR_NONE)
	{
		printf("inet_addr() error \"%s\"\n", targetIP);
		return EXIT_FAILURE;
	}
	connectionAddress.sin_addr.s_addr = raw_ip_nbo;
	result = clientLogic(srvSock, (const sockaddr*)&connectionAddress);

	if (result == EXIT_FAILURE)
	{
		return EXIT_FAILURE;
	}
	if (srvSock != INVALID_SOCKET)
	{
		result = closesocket(srvSock); //uzavreni socketu
		if (result != 0)
		{
			printf("closesocket() error %d\n", WSAGetLastError());
			return EXIT_FAILURE;
		}
		srvSock = INVALID_SOCKET;
	}
	return EXIT_SUCCESS;
}

int deaktivacesocketu(SOCKET socket)
{
	int result = shutdown(socket, SD_BOTH);
	if (result != 0)
	{
		printf("socket shutdown() error %d\n", WSAGetLastError());
	}
	result = closesocket(socket);
	if (result != 0)
	{
		printf("socket closesocket() error %d\n", WSAGetLastError());
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}


void datach(const sockaddr* connectionAddress) {

	
		dataSock = socket(
			AF_INET,
			SOCK_STREAM,
			IPPROTO_TCP);
		unsigned long argp = 1;
		if (ioctlsocket(dataSock,
			FIONBIO,
			&argp) == SOCKET_ERROR)
		{
			printf("ioctlsocket() error %d\n", WSAGetLastError());
			
		}


		setsockopt(dataSock,
			SOL_SOCKET,
			SO_REUSEADDR, //znovupouziti adressy
			(char*)&argp, sizeof(argp));

		connect(dataSock, connectionAddress, sizeof(sockaddr_in));


}


int clientLogic(SOCKET srvSock, const sockaddr* connectionAddress)
{
	int result, errorCode, connectionAttempts = 0;
	bool connectionWaiting = false;
	bool dataCH = false;
	

	// pripojovaci loopik
	do
	{
		if (!connectionWaiting)
		{
			result = connect(srvSock, connectionAddress, sizeof(sockaddr_in));
			errorCode = WSAGetLastError();
		}
		else
		{
			result = getStatus(srvSock, STATUS_WRITE);
			if (result != 0)
			{
				errorCode = result = WSAEISCONN;
			}
		}

		switch (errorCode)
		{
		case 0:
			connectionWaiting = true;
			break;
		case WSAEISCONN:
			printf("PRIPOJENO!\n");
			result = WSAEISCONN;
			break;
		case WSAEWOULDBLOCK:
		case WSAEALREADY:
			printf("cekani na pripojeni\r");
			connectionWaiting = true;
			break;
		case WSAEINVAL:
			printf("\ndivny argumenty\n");
			return EXIT_FAILURE;
		default:
			printf("\nclient connect() error %d\n", errorCode);
			return EXIT_FAILURE;
		}
	} while (result == SOCKET_ERROR || result == 0);

	// client loop
	int iterations = 0;
	bool sendit = false;
	int userTextFieldCursor = 0;
	int userInput;
	int prijato;
	int poci = 0;

	char okii1[] = { 0x01, 0x81, 0x00, 0x00 };
	char okii3[] = { 0x01, 0x83, 0x00, 0x00 };

	#define MAX_PACKET_SIZE 1000
	char reciveBufEnd[MAX_PACKET_SIZE];
	bool EndCH = false;
	SOCKET endSock = 0;

	int pp = 0;

	//RESET CONNECTION TOKENU
	std::ifstream i(CESTAD);
	json j;
	i >> j;
	i.close();
	j["connectionToken"] = nullptr;

	std::ofstream o(CESTAD);
	o << std::setw(4) << j.dump() << std::endl;
	o.close();


	while (1)
	{
		
		// receive data from the server, if there is any
		if (getStatus(srvSock, STATUS_READ) == 1)
		{
			unsigned long howMuchInBuffer = 0;
			unsigned long howMuchInBufferdata = 0;
			unsigned long numBytesRead = 0;
			unsigned long numBytesReaddata = 0;
			char recvbuf[4];
			char recvbufD[4];
			int resultd = 0;
			int payloadLength = 0;

			std::string hexStringD = "";

			printf("prijato: \"");
			do
			{
				ioctlsocket(srvSock, FIONREAD, &howMuchInBuffer);
				
				int result = recv(srvSock,
					recvbuf, sizeof(recvbuf), 0);

				

				//chyba je ve while loopu prijmu

				if (result == SOCKET_ERROR)
				{
					if (WSAGetLastError() != WSAEWOULDBLOCK && WSAGetLastError() != 0) {

						printf("client recv() error %d\n", WSAGetLastError());
						return EXIT_FAILURE;


					}
					result = 0;
					printf("zadna data\n");


				}


				std::string hexString = hexToString(recvbuf, result);
				

				switch (processResponse(hexString)) {

				case 1:
					send(srvSock, okii1, sizeof(okii1), 0);
					printf("POSLAN ping\n");
					break;
				case 2:
				{
					printf("prijat pozadavek na uvitani\n");

					std::string jsons = jsonToString(CESTA);
					char buffer[4024];
					memset(buffer, 0, sizeof(buffer));
					buffer[0] = 0x01;
					buffer[1] = 0x82;
					buffer[2] = 0x00;
					size_t jsonsLen = jsons.length();
					if (jsonsLen > 4019) {
						std::cerr << "Error: JSON string too long" << std::endl;
						return 1;
					}
					buffer[3] = static_cast<char>(jsonsLen);
					memcpy(buffer + 4, jsons.c_str(), jsonsLen);

					result = send(srvSock, buffer, jsonsLen + 4, 0);
					printf("POSLANY config\n");

					break;
				}
				case 3:
					const int bufferSize = 4096;
					char buffer[bufferSize];
					int totalBytesReceived = 0;
					int result;

					// Receive data from the socket
					while ((result = recv(srvSock, buffer + totalBytesReceived, bufferSize - totalBytesReceived, 0)) > 0) {
						totalBytesReceived += result;
					}

					// Check if the received data is valid
					if (totalBytesReceived > bufferSize) {
						std::cerr << "Error: received data exceeds buffer size" << std::endl;
						return 0;
					}

					try {
						// Print the received data
						std::cout << std::string(buffer, totalBytesReceived) << std::endl;

						// Convert the received data to a JSON object
						std::string str(buffer, totalBytesReceived);
						json js = stringToJson(str);

						// Print one object from the JSON array
						std::cout << "connection_token: " << js["connectionToken"].dump() << std::endl;

						// Save the connection token
						std::ifstream inputFile(CESTAD);
						json fileContents;
						inputFile >> fileContents;
						inputFile.close();
						fileContents["connectionToken"] = js["connectionToken"];

						std::ofstream outputFile(CESTAD);
						outputFile << std::setw(4) << fileContents.dump() << std::endl;
						outputFile.close();

						std::cout << "connection_token saved" << std::endl;
					}
					catch (const std::length_error& e) {

						std::cerr << "Error: " << e.what() << std::endl;
					}

					send(srvSock, okii3, sizeof(okii3), 0);
					printf("POSLANO oki 3\n");
					datach(connectionAddress);
					howMuchInBuffer = 4;




				}



				
				numBytesRead += result;
				howMuchInBuffer -= result;

				

			} while (howMuchInBuffer > 0);

			printf("\" %d bytes%c", numBytesRead,
				((numBytesRead != 0) ? '\n' : '\r'));
		}

		else if (getStatus(dataSock, STATUS_READ) == 1)
		{

			

			char recvbufD[4] = {0};
			//char recvbufDv[10] = {0};
			int resultd = 0;
			bool dataToResend = false;
			

			char recvbufDv[MAX_PACKET_SIZE];

			std::string hexStringD = "";

			printf("prijato: \"");
			do
			{
				ioctlsocket(dataSock, FIONREAD, &howMuchInBufferdata);

				if (dataCH) {

					// Define maximum packet size to prevent buffer overflow
					

					// Receive data packet
					struct sockaddr_in si_other;
					memset(&si_other, 0, sizeof(si_other));

					socklen_t slen = sizeof(si_other);

					resultd = recvfrom(dataSock, recvbufDv, MAX_PACKET_SIZE, 0, (struct sockaddr*)&si_other, &slen);

					if (resultd < 0) {
						perror("recvfrom");
						exit(1);
					}

				}
				else {
					resultd = recv(dataSock,
						recvbufD, sizeof(recvbufD), 0);
				}

				
				
				
				if (resultd == SOCKET_ERROR)
				{
					if (WSAGetLastError() != WSAEWOULDBLOCK && WSAGetLastError() != 0) {

						printf("client recv() error %d\n", WSAGetLastError());
						return EXIT_FAILURE;


					}
					resultd = 0;
					printf("zadna data\n");


				}

				if (dataCH) {

					printf("otevren kanal na data a je treba je zpracovat\n");
					
					// Parse the packet header
					uint8_t version = *(uint8_t*)(recvbufDv);
					uint32_t packetLength = ntohl(*(uint32_t*)(recvbufDv + 1));
					uint8_t packetType = *(uint8_t*)(recvbufDv + 5);
					
					cout << "version: " << (int)version << endl;
					cout << "packetLength: " << packetLength << endl;
					cout << "packetType: " << (bool)packetType << endl;
					

					
					if (packetType == 0) { // Control packet
						// Parse the control packet
						
						
						uint8_t controlFunction = *(uint8_t*)(recvbufDv + 9);
						

						// Print the information
						printf("------------------------------------------------------\n");
						printf("Control packet:\n");
						printf("Version: %d\n", version);
						printf("Packet length: %u\n", packetLength);
						printf("Control function: %u\n", controlFunction);
						printf("------------------------------------------------------\n");
					}
					else if (packetType == 1) { // Data packet
						printf("------------------------------------------------------\n");
						// Parse the endpoints
						uint16_t sourceEndpointLength = ntohs(*(uint16_t*)(recvbufDv + 6));
						uint8_t sourceEndpointTag = *(uint8_t*)(recvbufDv + 8);
						uint64_t SerializedEndpoint = ntohs(*(uint16_t*)(recvbufDv + 9));

						cout << "sourceEndpointLength: " << sourceEndpointLength << endl;
						cout << "sourceEndpointTag: " << (int)sourceEndpointTag << endl;
						cout << "SerializedEndpoint: " << SerializedEndpoint << endl;

						uint8_t EndpointType = *(uint8_t*)(recvbufDv + 10);
						uint16_t EndpointPort = ntohs(*(uint16_t*)(recvbufDv + 11));
						
						std::cout << "EndpointType: " << static_cast<int>(EndpointType) << std::endl;
						std::cout << "EndpointPort: " << EndpointPort << std::endl;
						
						uint8_t IPBytes[4];
						char ipAddress[INET_ADDRSTRLEN];

						std::memcpy(IPBytes, recvbufDv + 29, 4);

						
						if (inet_ntop(AF_INET, IPBytes, ipAddress, INET_ADDRSTRLEN) != nullptr) {
							std::cout << "IPv4 address: " << ipAddress << std::endl;
						}
						else {
							std::cout << "Failed to convert IPv4 address." << std::endl;
						}

						// Parse the send mode information
						uint16_t sendModeLength = ntohs(*(uint16_t*)(recvbufDv + 37));
						uint8_t sendModeTag = *(uint8_t*)(recvbufDv + 39);
						uint8_t sendModeFlags = *(uint8_t*)(recvbufDv + 40);

						cout << "sendModeLength: " << sendModeLength << endl;
						cout << "sendModeTag: " << (int)sendModeTag << endl;
						cout << "sendModeFlags: " << (int)sendModeFlags << endl;

						// Parse the payload information
						uint16_t payloadLength = ntohs(*(uint16_t*)(recvbufDv + 41));
						payloadLength = payloadLength - 3; //akculi nemam paru proc to tak je
						uint8_t payloadTag = *(uint8_t*)(recvbufDv + 43);

						

						char* payloadData = new char[payloadLength];
						memcpy(payloadData, (char*)(recvbufDv + 44), payloadLength);
						payloadData[payloadLength] = '\0'; 

						
						if (payloadData != 0) {

							endSock = socket(AF_INET, SOCK_DGRAM, 0);
							

							// Set up connection address
							sockaddr_in serverAddress{};
							serverAddress.sin_family = AF_INET;
							serverAddress.sin_port = htons(50000);
							if (inet_pton(AF_INET, "192.168.226.1", &(serverAddress.sin_addr)) <= 0) {
								std::cerr << "Invalid address" << std::endl;
								return 1;
							}

							// Connect to server
							if (connect(endSock, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
								std::cerr << "Connection failed" << std::endl;
								return 1;
							}

							// Send payload
							
							if (send(endSock, payloadData, strlen(payloadData), 0) < 0) {
								std::cerr << "Failed to send payload" << std::endl;
								return 1;
							}

							EndCH = true;

						}
						

						

						cout << "payloadLength: " << payloadLength << endl;
						cout << "payloadTag: " << (int)payloadTag << endl;
						cout << "payloadData: " << payloadData << endl;

						//clear all
						memset(recvbufDv, 0, sizeof(recvbufDv));
						payloadLength = 0;
						payloadTag = 0;
						sendModeLength = 0;
						sendModeTag = 0;
						sendModeFlags = 0;
						EndpointType = 0;
						EndpointPort = 0;
						



						printf("------------------------------------------------------\n");



					}
					else {
						printf("Unknown packet type: %d\n", packetType);
					}


					

				}

				else if (processResponse(hexToString(recvbufD, resultd)) == 2) {

					printf("prijat pozadavek na uvitani DATA\n");

					std::string jsons = jsonToString(CESTAD);
					char buffer[4024];
					memset(buffer, 0, sizeof(buffer));
					buffer[0] = 0x01;
					buffer[1] = 0x82;
					buffer[2] = 0x00;
					size_t jsonsLen = jsons.length();
					if (jsonsLen > 4019) {
						std::cerr << "Error: JSON string too long" << std::endl;
						return 1;
					}
					buffer[3] = static_cast<char>(jsonsLen);
					memcpy(buffer + 4, jsons.c_str(), jsonsLen);

					result = send(dataSock, buffer, jsonsLen + 4, 0);
					printf("POSLANY config na DATA\n");

					dataCH = 1;
				
				
				}

			


				numBytesReaddata += resultd;
				howMuchInBufferdata -= resultd;



			} while (howMuchInBufferdata > 0);

			printf("\" %d bytes on data%c", numBytesReaddata,
				((numBytesReaddata != 0) ? '\n' : '\r'));
		}

		else if (getStatus(endSock, STATUS_READ) == 1)
		{


			printf("prijato: \"");
			do
			{

				ioctlsocket(dataSock, FIONREAD, &howMuchInBufferend);

				
				if (EndCH) {


					struct sockaddr_in si_other;
					memset(&si_other, 0, sizeof(si_other));

					socklen_t slen = sizeof(si_other);

					int resultd = recvfrom(endSock, reciveBufEnd, MAX_PACKET_SIZE, 0, (struct sockaddr*)&si_other, &slen);

					if (resultd < 0) {
						perror("recvfrom");
						exit(1);
					}
					//print out the recived buffer to the console as ascii and hex values 

					printf("END POSILA \"");
					for (int i = 0; i < resultd; i++) {
						printf("%02x ", (unsigned char)reciveBufEnd[i]);
					}

				}




			} while (howMuchInBufferend > 0);

			printf("\" %d bytes on END%c", numBytesReadend,
				((numBytesReadend != 0) ? '\n' : '\r'));
		}



		else
		{
			printf("client: %d\n", iterations++);
		}
		
	}


	
	}


// status: 0x1 for read, 0x2 for write, 0x4 for exception
int getStatus(const SOCKET a_socket, int status)
{
	// zero seconds, zero milliseconds. max time select call allowd to block
	static timeval instantSpeedPlease = { 1,0 };
	fd_set a = { 1, {a_socket} };
	fd_set* read = ((status & 0x1) != 0) ? &a : NULL;
	fd_set* write = ((status & 0x2) != 0) ? &a : NULL;
	fd_set* except = ((status & 0x4) != 0) ? &a : NULL;
	/*
	select returns the number of ready socket handles in the fd_set structure, zero if the time limit expired, or SOCKET_ERROR if an error occurred. WSAGetLastError can be used to retrieve a specific error code.
	*/
	int result = select(0, read, write, except, &instantSpeedPlease);
	if (result == SOCKET_ERROR)
	{
		result = WSAGetLastError();
	}
	if (result < 0 || result > 3)
	{
		if (result != 10038) {
			printf("select(read) error %d\n", result);
			return SOCKET_ERROR;
		}
		
	}

	return result;
}

void finalWSACleanup() // callback used to clean up sockets
{
	int result = WSACleanup();
	if (result != 0)
	{
		printf("WSACleanup() error %d\n", result);
	}
}
