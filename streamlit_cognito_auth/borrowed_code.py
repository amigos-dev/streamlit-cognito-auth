# MIT License
# 
# Copyright (c) Mausam Gaurav
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


"""
Code borrowed from Mausam Gaurav.

Everything in this file was derived from
https://github.com/MausamGaurav/Streamlit_Multipage_AWSCognito_User_Authentication_Authorization, by Mausam Gaurav.

"""

from typing import Optional, Tuple, Dict
from .internal_types import JsonableDict

import requests
import base64
import json
import urllib.parse

import logging
logger = logging.Logger(__name__)

def raw_refresh_user_tokens(
        refresh_token: str,
        cognito_domain: str,
        client_id: str,
        client_secret: Optional[str]=None
    ) -> JsonableDict:
  """Given a new auth code, call AWS Cognito to generate the access token and ID token.

  Args:
      refresh_token (str):
          A refresh token as previously returned from raw_get_user_tokens.
      cognito_domain (str):
          The AWS Cognito User Pool endpoint URI; e.g.,
             "https://<user-pool-domain-prefix>.auth.<aws-region>.amazoncognito.com"
      client_id (str):
          The AWS Cognito Application Client ID used by this app
      client_secret (Optional[str], optional):
          The AWS Cognito Application Client Secret associate with
          client_id, or None if there is no secret for this application client.
          Defaults to None.

  Returns:
      JsonableDict similar to:
      {
        "access_token": "<access-token>",
        "expires_in": <secinds-to-access-token-expiration>,
        "id_token": <id-token>,
        "refresh_token": "<refresh-token>",
        "token-type": "Bearer"
      }
  """
  token_url = f"{cognito_domain}/oauth2/token"
  headers = {
      "Content-Type": "application/x-www-form-urlencoded",
    }
  if not client_secret is None and client_secret != '':
    client_secret_string = f"{client_id}:{client_secret}"
    client_secret_encoded = str(
        base64.b64encode(client_secret_string.encode("utf-8")), "utf-8"
      )
    headers["Authorization"] = f"Basic {client_secret_encoded}"
  body = {
      "grant_type": "refresh_token",
      "client_id": client_id,
      "refresh_token": refresh_token,
    }

  token_response = requests.post(token_url, headers=headers, data=body)
  token_response.raise_for_status()
  resp_obj = token_response.json()

  logger.info(f"OAUTH2 refresh token flow token response={json.dumps(resp_obj, indent=2, sort_keys=2)}")
  return resp_obj


def raw_get_user_tokens(
        auth_code: str,
        cognito_domain: str,
        client_id: str,
        redirect_uri: str,
        client_secret: Optional[str]=None
    ) -> JsonableDict:
  """Given a new auth code, call AWS Cognito to generate the access token and ID token.

  Args:
      auth_code (str):
          An authentication code passed in the "code" query parameter on
          redirect back from AWS Cognito Hosted UI.
      cognito_domain (str):
          The AWS Cognito User Pool endpoint URI; e.g.,
             "https://<user-pool-domain-prefix>.auth.<aws-region>.amazoncognito.com"
      client_id (str):
          The AWS Cognito Application Client ID used by this app
      redirect_uri (str):
          Must be the same redirect_uri used to initiate the AWS Cognito
          Hosted UI flow.
      client_secret (Optional[str], optional):
          The AWS Cognito Application Client Secret associate with
          client_id, or None if there is no secret for this application client.
          Defaults to None.

  Returns:
      JsonableDict similar to:
      {
        "access_token": "<access-token>",
        "expires_in": <secinds-to-access-token-expiration>,
        "id_token": <id-token>,
        "refresh_token": "<refresh-token>",
        "token-type": "Bearer"
      }
  """
  token_url = f"{cognito_domain}/oauth2/token"
  headers = {
      "Content-Type": "application/x-www-form-urlencoded",
    }
  if not client_secret is None and client_secret != '':
    client_secret_string = f"{client_id}:{client_secret}"
    client_secret_encoded = str(
        base64.b64encode(client_secret_string.encode("utf-8")), "utf-8"
      )
    headers["Authorization"] = f"Basic {client_secret_encoded}"
  body = {
      "grant_type": "authorization_code",
      "client_id": client_id,
      "code": auth_code,
      "redirect_uri": redirect_uri,
    }

  token_response = requests.post(token_url, headers=headers, data=body)
  token_response.raise_for_status()
  resp_obj = token_response.json()

  logger.info(f"OAUTH2 auth code flow token response={json.dumps(resp_obj, indent=2, sort_keys=2)}")
  return resp_obj


def raw_get_user_info(access_token: str, cognito_domain: str) -> JsonableDict:
  """Get logged-in user info from AWS Cognito

  Args:
      access_token (str):
          The logged-in session access token
      cognito_domain (str):
          The AWS Cognito User Pool endpoint URI; e.g.,
             "https://<user-pool-domain-prefix>.auth.<aws-region>.amazoncognito.com"

  Returns:
      JsonableDict:
          A deserialized JSON dict containing metadata about the logged-in user
  """
  userinfo_url = f"{cognito_domain}/oauth2/userInfo"
  headers = {
      "Content-Type": "application/json;charset=UTF-8",
      "Authorization": f"Bearer {access_token}",
  }

  resp = requests.get(userinfo_url, headers=headers)
  resp.raise_for_status()
  result = resp.json()
  if not isinstance(result, dict):
    raise TypeError("AWS Cognito userinfo endpoint returned non-dict result")
  return result

def _pad_base64(data: str) -> str:
  """Makes sure base64 data is padded.

  See https://gist.github.com/GuillaumeDerval/b300af6d4f906f38a051351afab3b95c

  Args:
      data (str):
          A base64 string which may or may not include trailing padding chars

  Returns:
      str: A base64 string which is properly padded
  """
  missing_padding = len(data) % 4
  if missing_padding != 0:
    data += "=" * (4 - missing_padding)
  return data

def raw_decode_token_payload(token: str) -> JsonableDict:
  """Decode the payload of an AWS Cognito ID or ACCESS token

  Args:
      token (str): An ID or ACCESS token string as provided by AWS Cognito token endpoint

  Returns:
      JsonableDict:
          A deserialized JSON dict containing the payload of the ID or ACCESS token
  """
  try:
    _header, payload, _signature = token.split(".")

    payload_json = base64.urlsafe_b64decode(_pad_base64(payload))
    payload: JsonableDict = json.loads(payload_json)

    if not isinstance(payload, dict):
      raise TypeError("AWS Cognito token payload is not a dict")
  except Exception as e:
    raise ValueError("Invalid ID or ACCESS token") from e

  return payload

def raw_get_login_link(
      cognito_domain: str,
      client_id: str,
      redirect_uri: str
    ) -> str:
  escaped_redirect_uri = urllib.parse.quote(redirect_uri.encode('utf8'))
  login_link = f"{cognito_domain}/login?client_id={client_id}&response_type=code&scope=email+openid&redirect_uri={escaped_redirect_uri}"
  return login_link
  
def raw_get_logout_link(
      cognito_domain: str,
      client_id: str,
      redirect_uri: str,
      redirect_query_params: Optional[Dict[str, str]]
    ) -> str:  
  if not redirect_query_params is None:
    first = True
    for k, v in redirect_query_params.items():
      escaped_v = urllib.parse.quote(v.encode('utf8'))
      redirect_uri += '?' if first else '&'
      redirect_uri += f"{k}={escaped_v}"
      first = False
  escaped_redirect_uri = urllib.parse.quote(redirect_uri.encode('utf8'))
  login_link = f"{cognito_domain}/logout?client_id={client_id}&logout_uri={escaped_redirect_uri}"
  return login_link

default_html_css_login = """
<style>
.button-login {
  background-color: skyblue;
  color: white !important;
  padding: 1em 1.5em;
  text-decoration: none;
  text-transform: uppercase;
}

.button-login:hover {
  background-color: #555;
  text-decoration: none;
}

.button-login:active {
  background-color: black;
}

</style>
"""

default_html_css_logout = default_html_css_login

def raw_get_login_button_html(login_link: str, html_css: Optional[str]=None) -> str:
  """Generates embeddable HTML for a Login button that navigates to
     AWS Cognito Hosted UI to log in.

     NOTE: The navigation will fail when the user clicks on the button
           if the streamlit app is hosted on streamlitapp.io.  This is because
           the host wraps the streamlit app in an iframe, which AWS Cognito
           prohibits for security reasons. This problem cannot be resolved
           until streamlit provits a way to navigate the main browser
           window.

           A workaround is to provide the user with login_link so they can paste
           it into their browser address bar.

  Args:
      login_link (str):
          The login link as returned from raw_get_login_link()
      html_css (Optional[str], optional):
          The <style> raw HTML block for the login button. A default is provided.

  Returns:
      str: Raw HTML that can be directly embedded with st.markdown()
  """
  if html_css is None:
    html_css = default_html_css_login
  html = html_css + f"<a href='{login_link}' class='button-login' target='_self'>Log In</a>"
  return html

def raw_get_logout_button_html(logout_link: str, html_css: Optional[str]=None) -> str:
  """Generates embeddable HTML for a Logout button that navigates to
     AWS Cognito Hosted UI to log out.

     NOTE: The navigation will fail when the user clicks on the button
           if the streamlit app is hosted on streamlitapp.io.  This is because
           the host wraps the streamlit app in an iframe, which AWS Cognito
           prohibits for security reasons. This problem cannot be resolved
           until streamlit provits a way to navigate the main browser
           window.

           A workaround is to provide the user with logout_link so they can paste
           it into their browser address bar.

  Args:
      logout_link (str):
          The logout link as returned from raw_get_logout_link()
      html_css (Optional[str], optional):
          The <style> raw HTML block for the login button. A default is provided.

  Returns:
      str: Raw HTML that can be directly embedded with st.markdown()
  """
  if html_css is None:
    html_css = default_html_css_logout
  html = html_css + f"<a href='{logout_link}' class='button-login' target='_self'>Log Out</a>"
  return html
