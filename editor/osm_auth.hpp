#pragma once

#include "std/string.hpp"

namespace osm
{

struct ClientToken
{
  string key;
  string secret;
};

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

  int AuthorizePassword(string const & login, string const & password, ClientToken & token);
  int AuthorizeFacebook(string const & facebookToken, ClientToken & token);
  bool IsAuthorized() { return m_token.key.empty(); }
  string Request(ClientToken & token, string const & method, string const & httpMethod = "GET", string const & body = "");

private:
  string m_consumerKey;
  string m_consumerSecret;
  string m_baseUrl;
  string m_apiUrl;
  ClientToken m_token;
};

}  // namespace osm
