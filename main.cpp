#include <iostream>
#include "DES.h"
using namespace std;

int main() {
	string key = "12345678";
	string msg = "qsdzyyds";

	DES des;
	des.generateKeys(key);
	auto bitmsg = DES::toUllong(msg);
	auto test = des.encode(bitmsg);
	test = des.decode(test);

	cout << (test == bitmsg ? "success" : "failed") << endl;
	cout << DES::toString(test) << endl;

	return 0;
}
