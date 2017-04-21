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
	std::string s = "004488cc115599dd2266aaee3377bbff\n";
	std::string in = "00112233445566778899AABBCCDDEEFF";
	a.init_state(in);
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), s); 
}

TEST(AESFixture, SubBytes_1)
{
	AES a = AES();
	std::string s = "631bc44b82fceec19333ac28c3f5ea16\n";
	std::string in = "00112233445566778899AABBCCDDEEFF";
	a.init_state(in);
	a.SubBytes();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), s); 
}

TEST(AESFixture, ShiftRows_1)
{
	AES a = AES();
	std::string s = "004488cc5599dd11aaee2266ff3377bb\n";
	std::string in = "00112233445566778899AABBCCDDEEFF";
	a.init_state(in);
	a.ShiftRows();
	std::ostringstream o;
	a.print_state(o);	
	ASSERT_EQ(o.str(), s);
}

TEST(AESFixture, MixColumns_1)
{
	AES a = AES();
	std::string in = "6036b4f1f37626913a18d69bcc4dbe18";
//	std::string in = "60f33acc3676184db426d6bef1919b18";
	std::string ans = "dfd011f23ae4f0972d6123cedb67ad8c\n";	
	a.init_state(in);
	a.MixColumns();
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), ans);
}
