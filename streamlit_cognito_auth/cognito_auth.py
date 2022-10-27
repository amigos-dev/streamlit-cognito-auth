# Copyright (c) 2022 Amigos Development Inc.
#
# MIT License - See LICENSE file accompanying this package.
#

from typing import Optional, Any, Tuple, List
from .internal_types import JsonableDict
from .logging import logger
import os
import sys
import json


import streamlit as st


from .borrowed_code import (
    raw_get_user_tokens,
    raw_get_user_info,
    raw_decode_id_token_payload,
    raw_get_login_link,
    raw_get_logout_link,
    raw_get_login_button_html,
    raw_get_logout_button_html,
  )

from .logging import logger

from dotenv import load_dotenv
load_dotenv()

class CognitoAuthConfig:
  session_state_var: str = "cognito_auth"
  cognito_domain: str
  client_id: str
  client_secret: Optional[str] = None
  app_uri: str = "http://localhost:8501/"
  html_css_login: Optional[str] = None
  html_css_logout: Optional[str] = None
  logged_in_fmt: Optional[str]
  in_sidebar: bool = True
  debug: bool = False

  def __init__(
        self,
        cognito_domain: Optional[str]=None,
        client_id: Optional[str]=None,
        app_uri: Optional[str]=None,
        client_secret: Optional[str]=None,
        debug: Optional[bool]=None,
        html_css_login: Optional[str] = None,
        html_css_logout: Optional[str] = None,
        logged_in_fmt: Optional[str] = "Logged in as {email}",
        in_sidebar: bool = True,
        session_state_var: str="cognito_auth",
      ):
    logger.debug("CognitoAuthConfig: initializing")
    if cognito_domain is None or cognito_domain == "":
      cognito_domain = os.environ.get('COGNITO_DOMAIN', '')
      if cognito_domain == '':
        raise RuntimeError("cognito_domain must be provided as an arg or in env var COGNITO_DOMAIN")
    self.cognito_domain = cognito_domain
    if client_id is None or client_id == "":
      client_id = os.environ.get('CLIENT_ID', '')
      if client_id == '':
        raise RuntimeError("client_id must be provided as an arg or in env var CLIENT_ID")
    self.client_id = client_id
    if app_uri is None or app_uri == "":
      app_uri = os.environ.get('APP_URI', '')
      if app_uri == '':
        app_uri = "http://localhost:8501/"
    self.app_uri = app_uri
    if client_secret is None:
      client_secret = os.environ.get('CLIENT_SECRET', '')
    if client_secret == '':
      client_secret = None
    self.client_secret = client_secret
    self.html_css_login = html_css_login
    self.html_css_logout = html_css_login if html_css_logout is None else html_css_logout
    self.logged_in_fmt = logged_in_fmt
    self.in_sidebar = in_sidebar
    self.session_state_var = session_state_var
    if debug is None:
      debug = '://localhost' in app_uri

class CognitoAuth:
  cfg: CognitoAuthConfig
  login_uri: str
  logout_uri: str

  def __init__(
        self,
        cfg: Optional[CognitoAuthConfig]=None
      ):
    if cfg is None:
      cfg = CognitoAuthConfig()
    logger.debug("CognitoAuth: initializing")
    self.cfg = cfg
    self.login_uri = raw_get_login_link(
        cognito_domain=self.cognito_domain,
        client_id=self.client_id,
        redirect_uri=self.app_uri
      )
    self.logout_uri = raw_get_logout_link(
        cognito_domain=self.cognito_domain,
        client_id=self.client_id,
        redirect_uri=self.app_uri,
        redirect_query_params=dict(action="logout")
      )
    logger.info(f'CognitoAuth: Login URI="{self.login_uri}"')
    logger.info(f'CognitoAuth: Logout URI="{self.logout_uri}"')

  def _get_session_var(self, name: str, default: Any=None) -> Any:
    return st.session_state.get(f"{self.cfg.session_state_var}_{name}", default)

  def _set_session_var(self, name: str, val: Any) -> None:
    st.session_state[f"{self.cfg.session_state_var}_{name}"] = val

  @property
  def cognito_domain(self) -> str:
    return self.cfg.cognito_domain

  @property
  def client_id(self) -> str:
    return self.cfg.client_id

  @property
  def client_secret(self) -> Optional[str]:
    return self.cfg.client_secret

  @property
  def app_uri(self) -> str:
    return self.cfg.app_uri

  @property
  def html_css_login(self) -> Optional[str]:
    return self.cfg.html_css_login

  @property
  def html_css_logout(self) -> Optional[str]:
    return self.cfg.html_css_logout

  @property
  def id_token(self) -> Optional[str]:
    return self._get_session_var('id_token')

  @id_token.setter
  def id_token(self, val: Optional[str]):
    if val != self.id_token:
      self._set_session_var('id_token', val)
      self._set_session_var('id_token_payload', None)
      self._set_session_var('cognito_groups', None)
      self.set_user_info(None)

  @property
  def access_token(self) -> Optional[str]:
    return self._get_session_var('access_token')

  @access_token.setter
  def access_token(self, val: Optional[str]):
    self._set_session_var('access_token', val)

  @property
  def auth_code(self) -> Optional[str]:
    return self._get_session_var('auth_code')

  @auth_code.setter
  def auth_code(self, val: Optional[str]):
    self._set_session_var('auth_code', val)

  @property
  def id_token_payload(self) -> Optional[JsonableDict]:
    result = self._get_session_var('id_token_payload')
    if result is None:
      id_token = self.id_token
      if not id_token is None:
        result = raw_decode_id_token_payload(id_token)
        self._set_session_var('id_token_payload', result)
    return result

  @property
  def cognito_groups(self) -> List[str]:
    result = self._get_session_var('cognito_groups')
    if result is None:
      id_token_payload = self.id_token_payload
      if not id_token_payload is None:
        result = id_token_payload.get('cognito:groups', None)
        if not result is None:
          if not isinstance(result, list):
            raise ValueError('Cognito id token field "cognito:groups" is not a list')
          self._set_session_var("cognito_groups", result)
    return result

  def get_user_info(self) -> Optional[JsonableDict]:
    result = self._get_session_var('user_info')
    if result is None:
      access_token = self.access_token
      if not access_token is None:
        result = raw_get_user_info(
            access_token=access_token,
            cognito_domain=self.cognito_domain
          )
        if not result is None:
          self._set_session_var('user_info', result)
    return result

  def set_user_info(self, val: Optional[JsonableDict]):
    self._set_session_var('user_info', val)

  def clear_login_state(self) -> None:
    self.id_token = None
    self.access_token = None
    self.auth_code = None
    self.set_user_info(None)

  def update_session_from_auth_code(self, auth_code: str) -> 'CognitoAuth':
    if auth_code == self.auth_code:
      logger.debug(f"CognitoAuth: got duplicate auth_code={auth_code}; ignoring")
    else:
      logger.debug(f"CognitoAuth: updating session from auth_code={auth_code}")
      self.clear_login_state()
      access_token, id_token = raw_get_user_tokens(
          auth_code=auth_code,
          cognito_domain=self.cognito_domain,
          client_id=self.client_id,
          redirect_uri=self.app_uri,
          client_secret=self.client_secret
        )
      logger.debug(f"CognitoAuth: Login successful; updated access_token and id_token")
      self.access_token = access_token
      self.id_token = id_token
      self.auth_code = auth_code
    return self

  def get_and_clear_query_param_logout_code(self) -> bool:
    query_params = dict(st.experimental_get_query_params())
    result = "action" in query_params and query_params["action"][0] == "logout"
    if result:
      del query_params['action']
      st.experimental_set_query_params(**query_params)
    return result

  def get_and_clear_query_param_auth_code(self) -> Optional[str]:
    auth_code = None
    query_params = dict(st.experimental_get_query_params())
    if "code" in query_params:
      auth_code = query_params["code"][0]
      del query_params["code"]
      if auth_code == '':
        auth_code = None
      st.experimental_set_query_params(**query_params)
    return auth_code

  def update(self) -> 'CognitoAuth':
    logger.debug("CognitoAuth: updating")
    if self.get_and_clear_query_param_logout_code():
      logger.debug("CognitoAuth: got action=logout queryparam; clearing login state")
      self.clear_login_state()
    auth_code = self.get_and_clear_query_param_auth_code()
    if not auth_code is None:
      logger.debug("CognitoAuth: got code queryparam; updating login state")
      self.update_session_from_auth_code(auth_code)
    #logger.debug(f"CognitoAuth: done updating, id_token_payload={json.dumps(self.id_token_payload, sort_keys=True)}")
    return self

  def get_login_button_html(self) -> str:
    return raw_get_login_button_html(self.login_uri, self.html_css_login)

  def get_logout_button_html(self) -> str:
    return raw_get_logout_button_html(self.logout_uri, self.html_css_logout)

  @property
  def user_email(self) -> Optional[str]:
    result = None
    id_token_payload = self.id_token_payload
    if not id_token_payload is None:
      result = id_token_payload.get('email', None)
      if not result is None and not isinstance(result, str):
        raise ValueError("id_token payload field 'email' is not a string")
    return result

  @property
  def user_email_is_verified(self) -> bool:
    result = False
    id_token_payload = self.id_token_payload
    if not id_token_payload is None:
      result = id_token_payload.get('email_verified', False)
      if not isinstance(result, bool):
        raise ValueError("id_token payload field 'email_verified' is not Boolean")
    return result

  @property
  def user_verified_email(self) -> Optional[str]:
    return None if not self.user_email_is_verified else self.user_email

  @property
  def user_is_authenticated(self) -> bool:
    return not self.user_email is None

  @property
  def user_is_verified(self) -> bool:
    return self.user_email_is_verified

  def user_is_in_cognito_group(self, group_name: str):
    user_email = self.user_email
    return not user_email is None and group_name in self.cognito_groups

  def user_is_in_any_cognito_group(self, group_names: List[str]):
    user_email = self.user_email
    if user_email is None:
      return False
    intersection = set(self.cognito_groups).intersection(group_names)
    return len(intersection) > 0

  @property
  def window_navigate_is_prohibited(self) -> bool:
    return '.streamlitapp.com/' in self.app_uri

  def login_button(self):
    st_target = st.sidebar if self.cfg.in_sidebar else st
    if self.window_navigate_is_prohibited:
      if st_target.button('Log In'):
        st.warning(f'Login is not seamlessly supported on this host because the streamlit app is running in an iframe. '
                   f'To login, copy and paste this link into your browser address bar:\n\n{self.login_uri}')
    else:
      st_target.markdown(self.get_login_button_html(), unsafe_allow_html=True)

  def logout_button(self):
    st_target = st.sidebar if self.cfg.in_sidebar else st
    #logger.debug(f"Displaying logout button, logged_in_fmt={self.cfg.logged_in_fmt}")
    if not self.cfg.logged_in_fmt is None:
      email = self.user_email
      if not email is None:
        logged_in_msg = self.cfg.logged_in_fmt.format(email=email)
        #logger.debug(f"Writing logged_in_msg: {logged_in_msg}")
        st_target.write(logged_in_msg)
    if self.window_navigate_is_prohibited:
      if st_target.button('Log Out'):
        st.warning(f'Logout is not seamlessly supported on this host because the streamlit app is running in an iframe. '
                   f'To login, copy and paste this link into your browser address bar:\n\n{self.logout_uri}')
    else:
      st_target.markdown(self.get_logout_button_html(), unsafe_allow_html=True)

  def button(self, in_sidebar: bool=True):
    if self.user_is_authenticated:
      self.logout_button()
    else:
      self.login_button()

  def require_authenticated(self) -> str:
    email = self.user_email
    if email is None:
      st.error('You are not logged in; please click on the "Log In" button to proceed')
      st.stop()
    return email

  def require_verified(self) -> str:
    email = self.require_authenticated()
    if not self.user_is_verified:
      st.error(f'You are logged in as user "{email}", but you have not yet verified your email address; please log out, verify your address, and try again.')
      st.stop()
    return email

  def require_cognito_group(self, group_name: str) -> str:
    email = self.require_authenticated()
    if not self.user_is_in_cognito_group(group_name):
      st.error(f'User "{email}" is not in required Cognito group "{group_name}". Please see your system administrator to be added.')
      st.stop()
    return email

  def require_any_cognito_group(self, group_names: List[str]) -> str:
    email = self.require_authenticated()
    if not self.user_is_in_any_cognito_group(group_names):
      st.error(f'User "{email}" is not in one of the authorized Cognito groups "{group_names}". Please see your system administrator to be added.')
      st.stop()
    return email

  def require_verified_cognito_group(self, group_name: str) -> str:
    email = self.require_verified()
    if not self.user_is_in_cognito_group(group_name):
      st.error(f'User "{email}" is not in required Cognito group "{group_name}". Please see your system administrator to be added.')
      st.stop()
    return email

  def require_any_verified_cognito_group(self, group_names: List[str]) -> str:
    email = self.require_verified()
    if not self.user_is_in_any_cognito_group(group_names):
      st.error(f'User "{email}" is not in one of the authorized Cognito groups "{group_names}". Please see your system administrator to be added.')
      st.stop()
    return email

_global_cognito_auth: Optional[CognitoAuth] = None
def cognito_auth(config_creator=None) -> CognitoAuth:
  global _global_cognito_auth
  result = _global_cognito_auth
  if result is None:
    if config_creator is None:
      config_creator = lambda: CognitoAuthConfig()
    elif isinstance(config_creator, CognitoAuthConfig):
      config_creator = lambda: config_creator
    cfg = config_creator()
    result = CognitoAuth(cfg)
    _global_cognito_auth = result
  return result