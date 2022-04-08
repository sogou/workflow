/*
  Copyright (c) 2021 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Wang Zhulei (wangzhulei@sogou-inc.com)
*/

#include <gtest/gtest.h>
#include "workflow/URIParser.h"

TEST(uriparser_unittest, parse)
{
	ParsedURI uri;

	EXPECT_EQ(URIParser::parse("https://john.doe:pass@www.example.com:123/forum/questions/?tag=networking&order=newest#top", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "https"), 0);
	EXPECT_EQ(strcmp(uri.userinfo, "john.doe:pass"), 0);
	EXPECT_EQ(strcmp(uri.host, "www.example.com"), 0);
	EXPECT_EQ(strcmp(uri.port, "123"), 0);
	EXPECT_EQ(strcmp(uri.path, "/forum/questions/"), 0);
	EXPECT_EQ(strcmp(uri.query, "tag=networking&order=newest"), 0);
	EXPECT_EQ(strcmp(uri.fragment, "top"), 0);

	EXPECT_EQ(URIParser::parse("https://john.doe@www.example.com:123/forum/questions/?tag=networking&order=newest#top", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "https"), 0);
	EXPECT_EQ(strcmp(uri.userinfo, "john.doe"), 0);
	EXPECT_EQ(strcmp(uri.host, "www.example.com"), 0);
	EXPECT_EQ(strcmp(uri.port, "123"), 0);
	EXPECT_EQ(strcmp(uri.path, "/forum/questions/"), 0);
	EXPECT_EQ(strcmp(uri.query, "tag=networking&order=newest"), 0);
	EXPECT_EQ(strcmp(uri.fragment, "top"), 0);

	EXPECT_EQ(URIParser::parse("ldap://[2001:db8::7]/c=GB?objectClass?one", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "ldap"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(strcmp(uri.host, "2001:db8::7"), 0);
	EXPECT_EQ(uri.port, nullptr);
	EXPECT_EQ(strcmp(uri.path, "/c=GB"), 0);
	EXPECT_EQ(strcmp(uri.query, "objectClass?one"), 0);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("ldap://user@[2001:db8::7]/c=GB?objectClass?one", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "ldap"), 0);
	EXPECT_EQ(strcmp(uri.userinfo, "user"), 0);
	EXPECT_EQ(strcmp(uri.host, "2001:db8::7"), 0);
	EXPECT_EQ(uri.port, nullptr);
	EXPECT_EQ(strcmp(uri.path, "/c=GB"), 0);
	EXPECT_EQ(strcmp(uri.query, "objectClass?one"), 0);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("ldap://user@[2001:db8::7]:12345/c=GB?objectClass?one", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "ldap"), 0);
	EXPECT_EQ(strcmp(uri.userinfo, "user"), 0);
	EXPECT_EQ(strcmp(uri.host, "2001:db8::7"), 0);
	EXPECT_EQ(strcmp(uri.port, "12345"), 0);
	EXPECT_EQ(strcmp(uri.path, "/c=GB"), 0);
	EXPECT_EQ(strcmp(uri.query, "objectClass?one"), 0);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("ldap://[2001:db8::7]:12345/c=GB?objectClass?one", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "ldap"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(strcmp(uri.host, "2001:db8::7"), 0);
	EXPECT_EQ(strcmp(uri.port, "12345"), 0);
	EXPECT_EQ(strcmp(uri.path, "/c=GB"), 0);
	EXPECT_EQ(strcmp(uri.query, "objectClass?one"), 0);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("mailto:John.Doe@example.com", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "mailto"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(uri.host, nullptr);
	EXPECT_EQ(uri.port, nullptr);
	EXPECT_EQ(strcmp(uri.path, "John.Doe@example.com"), 0);
	EXPECT_EQ(uri.query, nullptr);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("news:comp.infosystems.www.servers.unix", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "news"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(uri.host, nullptr);
	EXPECT_EQ(uri.port, nullptr);
	EXPECT_EQ(strcmp(uri.path, "comp.infosystems.www.servers.unix"), 0);
	EXPECT_EQ(uri.query, nullptr);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("tel:+1-816-555-1212", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "tel"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(uri.host, nullptr);
	EXPECT_EQ(uri.port, nullptr);
	EXPECT_EQ(strcmp(uri.path, "+1-816-555-1212"), 0);
	EXPECT_EQ(uri.query, nullptr);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("telnet://192.0.2.16:80/", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "telnet"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(strcmp(uri.host, "192.0.2.16"), 0);
	EXPECT_EQ(strcmp(uri.port, "80"), 0);
	EXPECT_EQ(strcmp(uri.path, "/"), 0);
	EXPECT_EQ(uri.query, nullptr);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("urn:oasis:names:specification:docbook:dtd:xml:4.1.2", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "urn"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(uri.host, nullptr);
	EXPECT_EQ(uri.port, nullptr);
	EXPECT_EQ(strcmp(uri.path, "oasis:names:specification:docbook:dtd:xml:4.1.2"), 0);
	EXPECT_EQ(uri.query, nullptr);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("https://www.example.com:123/forum/questions/?tag=networking&order=newest#top", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "https"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(strcmp(uri.host, "www.example.com"), 0);
	EXPECT_EQ(strcmp(uri.port, "123"), 0);
	EXPECT_EQ(strcmp(uri.path, "/forum/questions/"), 0);
	EXPECT_EQ(strcmp(uri.query, "tag=networking&order=newest"), 0);
	EXPECT_EQ(strcmp(uri.fragment, "top"), 0);

	EXPECT_EQ(URIParser::parse("https://john.doe@www.example.com/forum/questions/?tag=networking&order=newest#top", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "https"), 0);
	EXPECT_EQ(strcmp(uri.userinfo, "john.doe"), 0);
	EXPECT_EQ(strcmp(uri.host, "www.example.com"), 0);
	EXPECT_EQ(uri.port, nullptr);
	EXPECT_EQ(strcmp(uri.path, "/forum/questions/"), 0);
	EXPECT_EQ(strcmp(uri.query, "tag=networking&order=newest"), 0);
	EXPECT_EQ(strcmp(uri.fragment, "top"), 0);

	EXPECT_EQ(URIParser::parse("foo:/index.html", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "foo"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(uri.host, nullptr);
	EXPECT_EQ(uri.port, nullptr);
	EXPECT_EQ(strcmp(uri.path, "/index.html"), 0);
	EXPECT_EQ(uri.query, nullptr);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("http://www.test.cn/subject/ttt/index.html?abc-def-jki-lm-rstuvwxyz", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "http"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(strcmp(uri.host, "www.test.cn"), 0);
	EXPECT_EQ(uri.port, nullptr);
	EXPECT_EQ(strcmp(uri.path, "/subject/ttt/index.html"), 0);
	EXPECT_EQ(strcmp(uri.query, "abc-def-jki-lm-rstuvwxyz"), 0);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("http://sg.test1.com/zt/zz/#这是中文测试", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "http"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(strcmp(uri.host, "sg.test1.com"), 0);
	EXPECT_EQ(uri.port, nullptr);
	EXPECT_EQ(strcmp(uri.path, "/zt/zz/"), 0);
	EXPECT_EQ(uri.query, nullptr);
	EXPECT_EQ(strcmp(uri.fragment, "这是中文测试"), 0);

	EXPECT_EQ(URIParser::parse("http://www.test2.com?sg_vid=R_3qHh9H471Ry8OtW5J9R10vc_QR6EQqgA6HHLO6666666qe0Co66666666", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "http"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(strcmp(uri.host, "www.test2.com"), 0);
	EXPECT_EQ(uri.port, nullptr);
	EXPECT_EQ(uri.path, nullptr);
	EXPECT_EQ(strcmp(uri.query, "sg_vid=R_3qHh9H471Ry8OtW5J9R10vc_QR6EQqgA6HHLO6666666qe0Co66666666"), 0);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("https://sgsares.test3.com/ttts/中文测试_4115.apk", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "https"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(strcmp(uri.host, "sgsares.test3.com"), 0);
	EXPECT_EQ(uri.port, nullptr);
	EXPECT_EQ(strcmp(uri.path, "/ttts/中文测试_4115.apk"), 0);
	EXPECT_EQ(uri.query, nullptr);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("http://viptest.test5.com:8484?sg_vid=Rucnk5BKG81RcIVk7XySNhQtBODR6mKXA06PpWA66666663MTAfR6666666", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "http"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(strcmp(uri.host, "viptest.test5.com"), 0);
	EXPECT_EQ(strcmp(uri.port, "8484"), 0);
	EXPECT_EQ(uri.path, nullptr);
	EXPECT_EQ(strcmp(uri.query, "sg_vid=Rucnk5BKG81RcIVk7XySNhQtBODR6mKXA06PpWA66666663MTAfR6666666"), 0);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("http://viptest1.test6.com:84/abc#frag", uri), 0);
	EXPECT_EQ(strcmp(uri.scheme, "http"), 0);
	EXPECT_EQ(uri.userinfo, nullptr);
	EXPECT_EQ(strcmp(uri.host, "viptest1.test6.com"), 0);
	EXPECT_EQ(strcmp(uri.port, "84"), 0);
	EXPECT_EQ(strcmp(uri.path, "/abc"), 0);
	EXPECT_EQ(uri.query, nullptr);
	EXPECT_EQ(strcmp(uri.fragment, "frag"), 0);

	EXPECT_EQ(URIParser::parse("http://www.sogou.com", uri), 0);
	EXPECT_EQ(uri.path, nullptr);
	EXPECT_EQ(uri.query, nullptr);
	EXPECT_EQ(uri.fragment, nullptr);

	EXPECT_EQ(URIParser::parse("http://www.sogou.com?aaa/=bbb", uri), 0);
	EXPECT_EQ(uri.path, nullptr);
	EXPECT_EQ(strcmp(uri.query, "aaa/=bbb"), 0);
}

