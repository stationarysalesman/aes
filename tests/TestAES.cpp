#include <iostream>
#include "src/aes.h"
#include "gtest/gtest.h"

TEST(aesFixture, RotWord_1)
{
	aes a = aes();
	unsigned int w = 0x11223344;
	const unsigned int ans = 0x22334411;
	const unsigned int v = a.RotWord(w);
	ASSERT_EQ(v, ans);
}

TEST(aesFixture, RotWord_2)
{
	aes a = aes();
	unsigned int w = 0x00AABBCC;
	const unsigned int ans = 0xAABBCC00;
	const unsigned int v = a.RotWord(w);
	ASSERT_EQ(v, ans);
}

TEST(aesFixture, RotWord_3)
{
	aes a = aes();
	unsigned int w = 0x83ced71b;
	const unsigned int ans = 0xced71b83;
	const unsigned int v = a.RotWord(w);
	ASSERT_EQ(v, ans);
}

TEST(aesFixture, SubWord_1)
{
	aes a = aes();
	unsigned int w = 0x11223344;
	const unsigned int ans = 0x8293c31b;
	const unsigned int v = a.SubWord(w);
	ASSERT_EQ(v, ans);
}

TEST(aesFixture, SubWord_2)
{
	aes a = aes();
	unsigned int w = 0x925cef3d;
	const unsigned int ans = 0x4f4adf27;
	const unsigned int v = a.SubWord(w);
	ASSERT_EQ(v, ans);
}

TEST(aesFixture, SubWord_3)
{
	aes a = aes();
	unsigned int w = 0x83ced71b;
	const unsigned int ans = 0xec8b0eaf;
	const unsigned int v = a.SubWord(w);
	ASSERT_EQ(v, ans);
}

TEST(aesFixture, init_state_1)
{
	aes a = aes();
	std::string in = "00112233445566778899aabbccddeeff";
	a.init_state(in);
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), in+"\n"); 
}

TEST(aesFixture, SubBytes_1)
{
	aes a = aes();
	std::string s = "638293c31bfc33f5c4eeacea4bc12816\n"; 
	std::string in = "00112233445566778899aabbccddeeff";
	a.init_state(in);
	a.SubBytes();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), s); 
}

TEST(aesFixture, ShiftRows_1)
{
	aes a = aes();
	std::string s = "0055aaff4499ee3388dd2277cc1166bb\n"; 
	std::string in = "00112233445566778899aabbccddeeff";
	a.init_state(in);
	a.ShiftRows();
	std::ostringstream o;
	a.print_state(o);	
	ASSERT_EQ(o.str(), s);
}

TEST(aesFixture, MixColumns_1)
{
	aes a = aes();
	std::string in = "63fcac161bee28c3c4c193f54b8233ea";
	std::string ans = "6379e6d9f467fb76ad063cf4d2eb8aa3\n";	
	a.init_state(in);
	a.MixColumns();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), ans);
}

TEST(aesFixture, MixColumns_2)
{
	aes a = aes();
	std::string in = "e5c243c238f9120705783b1b9e46278f";
	std::string ans = "0d7dfc2a75e0ecada2a3267a45f41cdd\n";	
	a.init_state(in);
	a.MixColumns();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), ans);
}

TEST(aesFixture, MixColumns_3)
{
	aes a = aes();
	std::string in = "713aabf2f7f04b46f13f759c9ce19a54";
	std::string ans = "f5110bfdf3975b35518c9b61d5a4ae6c\n";	
	a.init_state(in);
	a.MixColumns();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), ans);
}

/* Decryption tests */

TEST(aesFixture, InvShiftRows_1)
{
	aes a = aes();
	std::string in = "0cfe055bcdc1da4a8f5f63caafb03f9d";
	std::string ans = "0cb0634acdfe3fca8fc1059daf5fda5b\n";	
	a.init_state(in);
	a.InvShiftRows();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), ans);
}

TEST(aesFixture, InvSubBytes_1)
{
	aes a = aes();
	std::string in = "604dd691f336be9b3a76b418cc1826f1";
	std::string ans = "90654aac7e245ae8a20fc6342734232b\n";
	a.init_state(in);
	a.InvSubBytes();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), ans);
}

TEST(aesFixture, InvMixColumns_1)
{
	aes a = aes();
	std::string in = "df3a2ddbd0e4616711f023adf297ce8c";
	std::string ans = "6036b4f1f37626913a18d69bcc4dbe18\n";	
	a.init_state(in);
	a.InvMixColumns();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), ans);
}

TEST(aesFixture, InvMixColumns_2)
{
	aes a = aes();
	std::string in = "929BC8F9BB384084DAB3353F60142964";
	std::string ans = "104d3a5f2e475b75cff4e6be5d5f665d\n";	
	a.init_state(in);
	a.InvMixColumns();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), ans);
}

TEST(aesFixture, InvMixColumns_3)
{
	aes a = aes();
	std::string in = "6379E6D9F467FB76AD063CF4D2EB8AA3";
	std::string ans = "63fcac161bee28c3c4c193f54b8233ea\n";	
	a.init_state(in);
	a.InvMixColumns();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), ans);
}

