#include "testing/testing.hpp"

#include "editor/osm_auth.hpp"

using osm::OsmOAuth;

namespace
{
constexpr string kTestServer = "http://188.166.112.124:3000";
constexpr string kConsumerKey = "QqwiALkYZ4Jd19lo1dtoPhcwGQUqMCMeVGIQ8Ahb";
constexpr string kConsumerSecret = "wi9HZKFoNYS06Yad5s4J0bfFo2hClMlH7pXaXWS3";
constexpr string kTestUser = "Testuser";
constexpr string kTestPassword = "test";
constexpr string kInvalidPassword = "123";
constexpr string kFacebookToken = "CAAYYoGXMFUcBAHZBpDFyFPFQroYRMtzdCzXVFiqKcZAZB44jKjzW8WWoaPWI4xxl9EK8INIuTZAkhpURhwSiyOIKoWsgbqZAKEKIKZC3IdlUokPOEuaUpKQzgLTUcYNLiqgJogjUTL1s7Myqpf8cf5yoxQm32cqKZAdozrdx2df4FMJBSF7h0dXI49M2WjCyjPcEKntC4LfQsVwrZBn8uStvUJBVGMTwNWkZD";
}  // namespace

UNIT_TEST(OSM_Auth_InvalidLogin)
{
  OsmOAuth auth(kConsumerKey, kConsumerSecret, kTestServer, kTestServer);
  TEST(!auth.IsAuthorized(), ("initial state not authorized"));
  ClientToken token;
  TEST_EQUAL(auth.AuthorizePassword(kTestUser, kInvalidPassword, token), OsmOAuth::AuthResult::FailLogin, ("invalid password"));
  TEST(!auth.IsAuthorized(), ("not authorized"));
}

UNIT_TEST(OSM_Auth_Login)
{
  OsmOAuth auth(kConsumerKey, kConsumerSecret, kTestServer, kTestServer);
  ClientToken token;
  TEST_EQUAL(auth.AuthorizePassword(kTestUser, kTestPassword, token), OsmOAuth::AuthResult::OK, ("login to test server"));
  TEST(auth.IsAuthorized(), ("authorized"));
  string const perm = auth.Request(token, "/permissions");
  TEST(perm.find("write_api") != string::npos, ("can write to api"));
}

UNIT_TEST(OSM_Auth_Facebook)
{
  OsmOAuth auth(kConsumerKey, kConsumerSecret, kTestServer, kTestServer);
  ClientToken token;
  TEST_EQUAL(auth.AuthorizeFacebook(kFacebookToken, token), OsmOAuth::AuthResult::OK, ("login via facebook"));
  TEST(auth.IsAuthorized(), ("authorized"));
  string const perm = auth.Request(token, "/permissions");
  TEST(perm.find("write_api") != string::npos, ("can write to api"));
}
