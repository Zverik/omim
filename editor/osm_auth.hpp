#pragma once

#include "std/string.hpp"

namespace osm
{

struct ClientToken
{
  string m_key;
  string m_secret;
  inline bool empty() { return m_key.empty() || m_secret.empty(); }
};

constexpr char const * kDefaultBaseURL = "https://www.openstreetmap.org";
constexpr char const * kDefaultApiURL = "https://aip.openstreetmap.org";
constexpr char const * kApiVersion = "/api/0.6";

class OsmOAuth
{
public:
  enum AuthResult
  {
    OK = 0,
    FailCookie = 1,
    FailLogin = 2,
    NoOAuth = 3,
    FailAuth = 4,
    NoAccess = 5
  };

  OsmOAuth(string const & consumerKey, string const & consumerSecret, string const & baseUrl = "https://www.openstreetmap.org", string const & apiUrl = "https://api.openstreetmap.org"):
      m_consumerKey(consumerKey),
      m_consumerSecret(consumerSecret),
      m_baseUrl(baseUrl),
      m_apiUrl(apiUrl)
  {
  }

  AuthResult AuthorizePassword(string const & login, string const & password, ClientToken & token);
  AuthResult AuthorizeFacebook(string const & facebookToken, ClientToken & token);
  string Request(ClientToken const & token, string const & method, string const & httpMethod = "GET", string const & body = "") const;

private:
  struct SessionID
  {
    string m_id;
    string m_token;
  };

  string m_consumerKey;
  string m_consumerSecret;
  string m_baseUrl;
  string m_apiUrl;

  bool FetchSessionId(SessionID & sid);
  bool LogoutUser(SessionID & sid);
  bool LoginUserPassword(string const & login, string const & password, SessionID & sid);
  bool LoginFacebook(string const & facebookToken, SessionID & sid);
  string SendAuthRequest(string const & requestTokenKey, SessionID & sid);
  AuthResult FetchAccessToken(SessionID & sid, ClientToken & token);
};

}  // namespace osm
