#include "editor/osm_auth.hpp"

#include "base/logging.hpp"
#include "coding/url_encode.hpp"
#include "std/iostream.hpp"
#include "std/map.hpp"
#include "3party/liboauthcpp/include/liboauthcpp/liboauthcpp.h"
#include "3party/Alohalytics/src/http_client.h"

using alohalytics::HTTPClientPlatformWrapper;

namespace osm
{

namespace
{
string const kOSMSessionCookie = "_osm_session";

string findAuthenticityToken(const string & body)
{
  string value;
  auto pos = body.find("name=\"authenticity_token\"");
  if (pos == string::npos)
    return value;
  pos = body.find("value=", pos);
  if (pos == string::npos)
    return value;
  while (pos < body.length() && body[pos] != '"')
    pos++;
  pos++;
  while (pos < body.length() && body[pos] != '"')
    value += body[pos++];
  return value;
}

string buildPostRequest(map<string, string> const & params)
{
  string result;
  for (auto it = params.begin(); it != params.end(); ++it)
  {
    if (it != params.begin())
      result += "&";
    result += it->first + "=" + UrlEncode(it->second);
  }
  return result;
}
}  // namespace

// Opens a login page and extract a cookie and a secret token.
bool OsmOAuth::FetchSessionId(OsmOAuth::SessionID & sid)
{
  HTTPClientPlatformWrapper request(m_baseUrl + "/login?cookie_test=true");
  if (!(request.RunHTTPRequest() && request.error_code() == 200))
    return false;
  sid.m_id = request.cookie_by_name(kOSMSessionCookie);
  sid.m_token = findAuthenticityToken(request.server_response());
  return !sid.m_id.empty() && !sid.m_token.empty();
}

// Log a user out.
bool OsmOAuth::LogoutUser(SessionID & sid)
{
  HTTPClientPlatformWrapper request(m_baseUrl + "/logout");
  request.set_cookies(kOSMSessionCookie + "=" + sid.m_id);
  request.RunHTTPRequest(); // we don't care for the result.
  return true;
}

// Signs a user id using login and password.
bool OsmOAuth::LoginUserPassword(string const & login, string const & password, SessionID & sid)
{
  map<string, string> params;
  params["username"] = login;
  params["password"] = password;
  params["referer"] = "/";
  params["commit"] = "Login";
  params["authenticity_token"] = sid.m_token;
  HTTPClientPlatformWrapper request(m_baseUrl + "/login");
  request.set_body_data(buildPostRequest(params), "application/x-www-form-urlencoded");
  request.set_cookies(kOSMSessionCookie + "=" + sid.m_id);
  if (!(request.RunHTTPRequest() && request.error_code() == 200 && request.was_redirected()))
    return false;
  return true;
}

// Signs a user in using a facebook token.
bool OsmOAuth::LoginFacebook(string const & facebookToken, SessionID & sid)
{
  string const url = m_baseUrl + "/auth/facebook_access_token/callback?access_token=" + facebookToken;
  HTTPClientPlatformWrapper request(url);
  request.set_cookies(kOSMSessionCookie + "=" + sid.m_id);
  if (!(request.RunHTTPRequest() && request.error_code() == 200 && request.was_redirected()))
    return false;
  return true;
}

// Fakes a buttons press, so a user accepts requested permissions.
string OsmOAuth::SendAuthRequest(string const & requestTokenKey, SessionID & sid)
{
  map<string, string> params;
  params["oauth_token"] = requestTokenKey;
  params["oauth_callback"] = "";
  params["authenticity_token"] = sid.m_token;
  params["allow_read_prefs"] = "yes";
  params["allow_write_api"] = "yes";
  params["commit"] = "Save changes";
  HTTPClientPlatformWrapper request(m_baseUrl + "/oauth/authorize");
  request.set_body_data(buildPostRequest(params), "application/x-www-form-urlencoded");
  request.set_cookies(kOSMSessionCookie + "=" + sid.m_id);

  if (!request.RunHTTPRequest())
    return string();

  string const callbackURL = request.url_received();
  string const vKey = "oauth_verifier=";
  auto const pos = callbackURL.find(vKey);
  if (pos == string::npos)
    return string();
  auto const end = callbackURL.find("&", pos);
  return callbackURL.substr(pos + vKey.length(), end == string::npos ? end : end - pos - vKey.length()+ 1);
}

// Given a web session id, fetches an OAuth access token.
OsmOAuth::AuthResult OsmOAuth::FetchAccessToken(SessionID & sid, ClientToken & token)
{
  // Aquire a request token.
  OAuth::Consumer consumer(m_consumerKey, m_consumerSecret);
  OAuth::Client oauth(&consumer);
  string const requestTokenUrl = m_baseUrl + "/oauth/request_token";
  string const requestTokenQuery = oauth.getURLQueryString(OAuth::Http::Get, requestTokenUrl + "?oauth_callback=oob");
  HTTPClientPlatformWrapper request(requestTokenUrl + "?" + requestTokenQuery);
  if (!(request.RunHTTPRequest() && request.error_code() == 200 && !request.was_redirected()))
    return OsmOAuth::AuthResult::NoOAuth;
  OAuth::Token requestToken = OAuth::Token::extract(request.server_response());
  
  // Faking a button press for access rights.
  string const pin = SendAuthRequest(requestToken.key(), sid);
  if (pin.empty())
    return OsmOAuth::AuthResult::FailAuth;
  requestToken.setPin(pin);

  // Got pin, exchange it for the access token.
  oauth = OAuth::Client(&consumer, &requestToken);
  string const accessTokenUrl = m_baseUrl + "/oauth/access_token";
  string const queryString = oauth.getURLQueryString(OAuth::Http::Get, accessTokenUrl, "", true);
  HTTPClientPlatformWrapper request2(accessTokenUrl + "?" + queryString);
  if (!(request2.RunHTTPRequest() && request2.error_code() == 200 && !request2.was_redirected()))
    return AuthResult::NoAccess;
  OAuth::KeyValuePairs responseData = OAuth::ParseKeyValuePairs(request2.server_response());
  OAuth::Token accessToken = OAuth::Token::extract(responseData);

  token.m_key = accessToken.key();
  token.m_secret = accessToken.secret();

  LogoutUser(sid);
  
  return OsmOAuth::AuthResult::OK;
}

OsmOAuth::AuthResult OsmOAuth::AuthorizePassword(string const & login, string const & password, ClientToken & token)
{
  SessionID sid;
  if (!FetchSessionId(sid))
    return OsmOAuth::AuthResult::FailCookie;

  if (!LoginUserPassword(login, password, sid))
    return OsmOAuth::AuthResult::FailLogin;

  return FetchAccessToken(sid, token);
}

OsmOAuth::AuthResult OsmOAuth::AuthorizeFacebook(string const & facebookToken, ClientToken & token)
{
  SessionID sid;
  if (!FetchSessionId(sid))
    return OsmOAuth::AuthResult::FailCookie;

  if (!LoginFacebook(facebookToken, sid))
    return OsmOAuth::AuthResult::FailLogin;

  return FetchAccessToken(sid, token);
}

string OsmOAuth::Request(ClientToken const & token, string const & method, string const & httpMethod, string const & body) const
{
  // TODO(@zverik): Support other http methods
  OAuth::Consumer const consumer(m_consumerKey, m_consumerSecret);
  OAuth::Token const oatoken(token.m_key, token.m_secret);
  OAuth::Client oauth(&consumer, &oatoken);

  string const url = m_apiUrl + kApiVersion + method;
  string const query = oauth.getURLQueryString(OAuth::Http::Get, url);

  HTTPClientPlatformWrapper request(url + "?" + query);
  if (request.RunHTTPRequest() && request.error_code() == 200 && !request.was_redirected())
    return request.server_response();

  return string();
}

}  // namespace osm
