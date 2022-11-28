# Cased CLI

## About

* cased-cli is an open source SSH client that brings the power of Cased to everyone's local terminal
* Project status: working/prototype

## Table of contents

> * [Cased CLI](#cased-cli)
>   * [About / Synopsis](#about)
>   * [Table of contents](#table-of-contents)
>   * [Installation](#installation)
>   * [Usage](#usage)
>     * [Configuration](#configuration)
>     * [Authentication](#authenticate--on--Cased--Shell)
>     * [Snippets](#snippets)
>   * [Contributing / Reporting issues](#contributing--reporting-issues)
>   * [License](#license)
>   * [About Cased](#about-cased)

## Installation

### Cased GitHub codespaces


To get `cased-cli` installed in a codespace enviroment, just run the following command: `GOPRIVATE=github.com go install github.com/cased/cased-cli@latest`

### Linux, MacOS and WSL systems

`cased-cli` can be installed using the `go` tool, but since `cased-cli` is currently in a GitHub private repository, the following steps are required to get it properly installed:

  - [Generate a new personal access token](https://github.com/settings/tokens/new?scopes=read:packages)
  - Authorize the [token](https://github.com/settings/tokens) you just created to access Cased's GitHub Organization.
  - Create a `~/.netrc` file to provide authentication instructions for go/git .

Example ~/.netrc file:
```
$ nano ~/.netrc
machine github.com
login your_github_username
password your_github_access_token
```

The login value should be your GitHub username.

The password value should be the [GitHub personal access token](https://docs.github.com/en/github/authenticating-to-github/keeping-your-account-and-data-secure/creating-a-personal-access-token) you created.

Finally, run the following command to get `cased-cli` installed on your local machine: `GOPRIVATE=github.com/cased/cased-cli go install github.com/cased/cased-cli@latest`

### Manually cloning and building the project

1. Clone cased-cli [repository](https://github.com/cased/cased-cli):
    - `git clone https://github.com/cased/cased-cli` 
2. Build the program:  
    - `cd cased-cli`
    - `go build`

## Usage

-  Run `$ cased-cli auth instance.domain`, where instance.domain is the domain name where [cased-shell](https://github.com/cased/shell) was installed and running:
  <p>
    <img src="https://github.com/cased/cased-cli/blob/main/images/auth.png" alt="Sample authentication using cased-shell running on a GitHub codespaces">
  </p>
-  A web browser should popup asking the user to fill in login credentials:
  <p>
    <img src="https://github.com/cased/cased-cli/blob/main/images/login_idp.png" alt="Login Credentials">
  </p>
- If authentication is successful, a message will be displayed in the web browser, the user can close the web-browser/tab and back to the terminal:
  <p>
    <img src="https://github.com/cased/cased-cli/blob/main/images/login_ok.png" alt="Login OK">
  </p>
- After a successfull authentication, `cased-cli` displays a list of available prompts in the terminal.
- Users can navigate the list using up/down arrow key.
- A '/' key triggers the search, which allows users to filter prompts by name/description.
- Pressing 'q' will exit the program.
- Finally, pressing <ENTER> will connect to the currently selected prompt in the list:
  <p>
    <img src="https://github.com/cased/cased-cli/blob/main/images/connecting.png" alt="Connecting to a prompt">
  </p>
- When connected to a prompt, the user can interact with it as usual, running `exit` command should get the user back to the prompts screen.
- Pressing '/' during a SSH session will trigger the [snippets](#snippets) screen
- If the web browser fails to open, users will be provided with a unique URL where they can try to authenticate manually.

## Local Development
- `cased-cli` currently supports the following enviroment variables to allow for local development/testing:

| Variable         | Format            | Description                                                                                                           |
|------------------|-------------------|-----------------------------------------------------------------------------------------------------------------------|
| CASED_SERVER     | host:port         | Specify the network address where `cased-server` is listening. Default port is 6565.                                  |
| CASED_SERVER_API | https://host:port | Specify the address where `cased-server` API is listening. Default is https://IP:6566.                                |
| TLS_SKIP_VERIFY  | true\|false       | When developing locally, a self-signed TLS certificate is used, to allow `cased-cli` to work set TLS_SKIP_VERIFY=true |

- Example (on Linux/Bash), assuming `cased-server` is running on the same machine as `cased-cli`:
```
$ export CASED_SERVER=localhost:6565
$ export CASED_SERVER_API=https://localhost:6566
$ export TLS_SKIP_VERIFY=true
$ ./cased-cli auth <domain>
```

### Snippets
- Type `/` during a SSH session (it must be the first character in the command line)
- A screen similar to the one bellow should be displayed (if snippets are available):
  <p>
    <img src="https://github.com/cased/cased-cli/blob/main/images/snippets_1.png" alt="Snippets Menu">
  </p>
- The snippets are organized in categories, each category has its own tab.
- To navigate between snippet categories use the left anf right arrows in the keyboard.
- To search for a snippet press the '/' key, pressing <ESC> will get back to the previous screen.
- Pressing 'q' will exit the snippets screen and get user back to the shell.
- Press UP/Down keys to navigate between snippets in the current selected tab/category.
- Press <ENTER> to select a snippet, in the next screen the user can edit the snippet arguments, press <ENTER> again to submit, or use the [Submit] button. Press <ESC> to get back to the previous menu.
- 
## Contributing / Reporting issues

### Creating a release

```
git tag -a v0.0.1
git push origin v0.0.1
```

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.html)

## About Cased

More information is available at [www.cased.com](https://www.cased.com).
