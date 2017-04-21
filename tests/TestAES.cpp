#include <iostream>
#include "src/AES.h"
#include "gtest/gtest.h"

TEST(AESFixture, RotWord_1)
{
	AES a = AES();
	unsigned int w = 0x11223344;
	const unsigned int ans = 0x22334411;
	const unsigned int v = a.RotWord(w);
	ASSERT_EQ(v, ans);
}

TEST(AESFixture, RotWord_2)
{
	AES a = AES();
	unsigned int w = 0x00AABBCC;
	const unsigned int ans = 0xAABBCC00;
	const unsigned int v = a.RotWord(w);
	ASSERT_EQ(v, ans);
}

TEST(AESFixture, RotWord_3)
{
	AES a = AES();
	unsigned int w = 0x83ced71b;
	const unsigned int ans = 0xced71b83;
	const unsigned int v = a.RotWord(w);
	ASSERT_EQ(v, ans);
}

TEST(AESFixture, SubWord_1)
{
	AES a = AES();
	unsigned int w = 0x11223344;
	const unsigned int ans = 0x8293c31b;
	const unsigned int v = a.SubWord(w);
	ASSERT_EQ(v, ans);
}

TEST(AESFixture, SubWord_2)
{
	AES a = AES();
	unsigned int w = 0x925cef3d;
	const unsigned int ans = 0x4f4adf27;
	const unsigned int v = a.SubWord(w);
	ASSERT_EQ(v, ans);
}

TEST(AESFixture, SubWord_3)
{
	AES a = AES();
	unsigned int w = 0x83ced71b;
	const unsigned int ans = 0xec8b0eaf;
	const unsigned int v = a.SubWord(w);
	ASSERT_EQ(v, ans);
}

TEST(AESFixture, init_state_1)
{
	AES a = AES();
	std::string in = "00112233445566778899aabbccddeeff";
	a.init_state(in);
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), in+"\n"); 
}

TEST(AESFixture, SubBytes_1)
{
	AES a = AES();
	std::string s = "638293c31bfc33f5c4eeacea4bc12816\n"; 
	std::string in = "00112233445566778899aabbccddeeff";
	a.init_state(in);
	a.SubBytes();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), s); 
}

TEST(AESFixture, ShiftRows_1)
{
	AES a = AES();
	std::string s = "0055aaff4499ee3388dd2277cc1166bb\n"; 
	std::string in = "00112233445566778899aabbccddeeff";
	a.init_state(in);
	a.ShiftRows();
	std::ostringstream o;
	a.print_state(o);	
	ASSERT_EQ(o.str(), s);
}

TEST(AESFixture, MixColumns_1)
{
	AES a = AES();
	std::string in = "63fcac161bee28c3c4c193f54b8233ea";
	std::string ans = "6379e6d9f467fb76ad063cf4d2eb8aa3\n";	
	a.init_state(in);
	a.MixColumns();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), ans);
}

TEST(AESFixture, MixColumns_2)
{
	AES a = AES();
	std::string in = "e5c243c238f9120705783b1b9e46278f";
	std::string ans = "0d7dfc2a75e0ecada2a3267a45f41cdd\n";	
	a.init_state(in);
	a.MixColumns();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), ans);
}

TEST(AESFixture, MixColumns_3)
{
	AES a = AES();
	std::string in = "713aabf2f7f04b46f13f759c9ce19a54";
	std::string ans = "f5110bfdf3975b35518c9b61d5a4ae6c\n";	
	a.init_state(in);
	a.MixColumns();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), ans);
}
