# streamlit-cognito-auth
streamlit-cognito-auth: Easy Authentication and Authorization of Streamlit apps using AWS Cognito
=================================================================================================

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Latest release](https://img.shields.io/github/v/release/amigos-dev/streamlit-cognito-auth.svg?style=flat-square&color=b44e88)](https://github.com/amigos-dev/streamlit-cognito-auth/releases)

A package that can be included in Streamlit apps to provide secure authentication and authorization against AWS Cognito

Table of contents
-----------------

* [Introduction](#introduction)
* [Installation](#installation)
* [Usage](#usage)
  * [Command line](#command-line)
  * [API](api)
* [Known issues and limitations](#known-issues-and-limitations)
* [Getting help](#getting-help)
* [Contributing](#contributing)
* [License](#license)
* [Authors and history](#authors-and-history)


Introduction
------------

Python package `streamlit-cognito-auth` provides simple tools that can be included in a streamlit application to
require user authentication and authorization against an AWS Cognito User Pool.

Some key features of streamlit-cognito-auth:

* Provides a simple *Log In*/*Log Out* UI element that can be placed in the streamlit sidebar.
* Full power of AWS Cognito Hosted UI for login.
* User self-registration/email verification provided by AWS Cognito.
* Simple configuration using environment variables or streamlit secrets.
* Fine-grained authorization using AWS congnito user groups.


Installation
------------

### Prerequisites

#### AWS Cognito User Pool

Before this package can be used, you must create an AWS Cognito User Pool
and an associated AWS Cognito App Client for use by your streamlit
app. A great walkthru by [Mausam Gaurav](https://github.com/MausamGaurav) on how to properly configure AWS Cognito can
be found [here](https://levelup.gitconnected.com/building-a-multi-page-app-with-streamlit-and-restricting-user-access-to-pages-using-aws-cognito-89a1fb5364a3#6c20).
Note that only the instructions for "Configuring AWS Cognito" on that page should be followed.

After you have created an AWS Cognito User Pool and associated AWS Cognito App Client,
make note of the following configuration values:

- _COGNITO_DOMAIN_ is the HTTPS URL of the cognito userpool
  endpoint; e.g., "https://_user-pool-domain-prefix_.auth._aws-region_.amazoncognito.com".
- _CLIENT_ID_ is the id of the AWS Cognito Application Client to be used by the streamlit app.
- _CLIENT_SECRET_ is an optionally configured client secret associated with the AWS Cognito Application Client. Note
  that if the streamlit app is hosted on a public site, this secret will be exposed to anyone who wants it, so it
  does not add much security value.  However, it is not essential to the overall security model and cannot hurt.

#### Python

Python 3.7+ is required. See your OS documentation for instructions.

### Installing the latest release with pip
```bash
pip3 install streamlit-cognito-auth
```

### Installing the latest release from GitHub with pip
```bash
pip3 install "git+https://github.com/amigos-dev/streamlit-cognito-auth@$(curl -s https://api.github.com/repos/amigos-dev/streamlit-cognito-auth/releases/latest | jq -r ".tag_name")"
```

### Installing the development project from GitHub with Poetry

This is useful if you wish to contribute to the project.

[Poetry](https://python-poetry.org/docs/master/#installing-with-the-official-installer) is required; it can be installed with:

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

Clone the repository and install streamlit-cognito-auth into a private virtualenv with:

```bash
cd <parent-folder>
git clone https://github.com/migos-dev/streamlit-cognito-auth.git
cd streamlit-cognito-auth
poetry install
```

You can then launch a bash shell with the virtualenv activated using:

```bash
poetry shell
```


Usage
=====

Command Line
------------

There is a single command tool `streamlit-cognito-auth` that is installed with the package.

### Running a generic activity task worker

To start a generic activity task worker that can run arbitrary shell scripts:

```bash

cd <worker-data-parent-dir>
streamlit-cognito-auth [-p <AWS-profile>] [-r <AWS-region>]  -a <AWS-stepfunction-activity-name> -w <unique-worker-name> run
```

The task worker will keep running until it is stopped; e.g., with Ctrl-C.


API
---

TBD

Known issues and limitations
----------------------------

* Unfortunately, seamless integration with Cognito Hosted UI is not possible when the streamlit app is hosted on
 [Streamlit Community Cloud](https://share.streamlit.io/). This is because the host wraps the streamlit app in a sandboxed HTML \<iframe\> tag. This forces navigation to Cognito's Hosted UI to be constrained to the iframe. Cognito forbids that for security reasons. Streamlit does not currently provide any way for the hosted app to navigate the main browser window. As a workaround, if the app is hosted on *.streamlitapp.io,
then when the user clicks on _Log In_ or _Log Out_, no navigation will take place, but a warning box will be displayed with an explanation and a hyperlink that the user can manually cut and pasdte into the browser address bar to log in or out.

Getting help
------------

Please report any problems/issues [here](https://github.com/amigos-dev/streamlit-cognito-auth/issues).

Contributing
------------

Pull requests welcome.

License
-------

streamlit-cognito-auth is distributed under the terms of the [MIT License](https://opensource.org/licenses/MIT).  The license applies to this file and other files in the [GitHub repository](http://github.com/amigos-dev/streamlit-cognito-auth) hosting this file.

Authors and history
---------------------------

The initial author of streamlit-cognito-auth is [Sam McKelvie](https://github.com/sammck).
It is maintained by [amigos.dev](https://amigos.dev).

Portions of this package are derived from [this working streamlit example](https://github.com/MausamGaurav/Streamlit_Multipage_AWSCognito_User_Authentication_Authorization) by [Mausam Gaurav](https://github.com/MausamGaurav). Such derivative files are individually annotated with a License.
