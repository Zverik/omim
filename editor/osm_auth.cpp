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
  string const kOSMUserNameCookie = "_osm_username";

string findAuthenticityToken(const string & body)
{
  string value;
  int pos = body.find("name=\"authenticity_token\"");
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

string buildPostRequest(const map<string, string> & params)
{
  string result = "";
  bool first = true;
  for (std::pair<string, string> kv : params)
  {
    if (first)
      first = false;
    else
      result += '&';
    result += kv.first + '=' + UrlEncode(kv.second);
  }
  return result;
}

struct SessionID
{
  string id;
  string token;
};

// Opens a login page and extract a cookie and a secret token.
bool fetchSessionId(SessionID & sid)
{
  HTTPClientPlatformWrapper request(m_baseUrl + "/login?cookie_test=true");
  if (!(request.RunHTTPRequest() && request.error_code() == 200))
    return false;
  sid.id = request.cookie_by_name(kOSMSessionCookie);
  sid.token = findAuthenticityToken(request.server_response());
  return !sid.id.empty() && !sid.token.empty();
}

// Log a user out.
bool logoutUser(SessionID & sid)
{
  HTTPClientPlatformWrapper request(m_baseUrl + "/logout");
  request.set_cookies(kOSMSessionCookie + "=" + sid.id);
  request.RunHTTPRequest(); // we don't care for the result.
  return true;
}

// Signs a user id using login and password.
bool loginUserPassword(string const & login, string const & password, SessionID & sid)
{
  map<string, string> params;
  params["username"] = login;
  params["password"] = password;
  params["referer"] = "/";
  params["commit"] = "Login";
  params["authenticity_token"] = sid.token;
  HTTPClientPlatformWrapper request(m_baseUrl + "/login");
  request.set_body_data(buildPostRequest(params), "application/x-www-form-urlencoded");
  request.set_cookies(kOSMSessionCookie + "=" + sid.id);
  if (!(request.RunHTTPRequest() && request.error_code() == 200 && request.was_redirected()))
    return false;
  return true;
}

// Signs a user in using a facebook token.
bool loginFacebook(string const & facebookToken, SessionID & sid)
{
  string const url = m_baseUrl + "/auth/facebook_access_token/callback?access_token=" + facebook_access_token;
  HTTPClientPlatformWrapper request(url);
  request.set_cookies(kOSMSessionCookie + "=" + sid.id);
  if (!(request.RunHTTPRequest() && request.error_code() == 200 && request.was_redirected()))
    return false;
  return true;
}

// Fakes a buttons press, so a user accepts requested permissions.
string sendAuthRequest(string const & requestTokenKey, SessionID & sid)
{
  map<string, string> params;
  params["oauth_token"] = requestTokenKey;
  params["oauth_callback"] = "";
  params["authenticity_token"] = sid.token;
  params["allow_read_prefs"] = "yes";
  params["allow_write_api"] = "yes";
  params["commit"] = "Save changes";
  HTTPClientPlatformWrapper request(m_baseUrl + "/oauth/authorize");
  request.set_body_data(buildPostRequest(params), "application/x-www-form-urlencoded");
  request.set_cookies(kOSMSessionCookie + "=" + sid.id);

  if (!request.RunHTTPRequest())
    return string();

  string callbackURL = request.url_received();
  string const vKey = "oauth_verifier=";
  auto pos = callbackURL.find(vKey);
  if (pos == string::npos)
    return string();
  auto end = callbackURL.find("&", pos);
  return callbackURL.substr(pos + vKey.length(), end == string::npos ? end : end - pos - vKey.length()+ 1);
}

// Given a web session id, fetches an OAuth access token.
int fetchAccessToken(SessionID & sid, ClientToken & token)
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
  string pin = sendAuthRequest(requestToken.key(), sid);
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

  token.key = accessToken.key();
  token.secret = accessToken.secret();

  logoutUser(sid);
  
  return OsmOAuth::AuthResult::OK;
}
}  // namespace

int OsmOAuth::AuthorizePassword(string const & login, string const & password, ClientToken & token)
{
  SessionID sid;
  if (!fetchSessionId(sid))
    return OsmOAuth::AuthResult::FailCookie;

  if (!loginUserPassword(login, password, sid))
    return OsmOAuth::AuthResult::FailLogin;

  return fetchAccessToken(sid, token);
}

int OsmOAuth::AuthorizeFacebook(string const & facebookToken, ClientToken & token)
{
  SessionID sid;
  if (!fetchSessionId(sid))
    return OsmOAuth::AuthResult::FailCookie;

  if (!loginFacebook(facebookToken, sid))
    return OsmOAuth::AuthResult::FailLogin;

  return fetchAccessToken(sid, token);
}

string OsmOAuth::Request(ClientToken & token, string const & method, string const & httpMethod = "GET", string const & body = "")
{
  // TODO(@zverik): Support other http methods
  OAuth::Consumer consumer(m_consumerKey, m_consumerSecret);
  OAuth::Token oatoken(token.key, token.secret);
  OAuth::Client oauth(&consumer, &oatoken);

  string url = m_apiUrl + method;
  string query = oauth.getURLQueryString(OAuth::Http::Get, url);

  HTTPClientPlatformWrapper request(url + "?" + query);
  if (request.RunHTTPRequest() && request.error_code() == 200)
    return request.server_response();

  return string();
}

}  // namespace osm
