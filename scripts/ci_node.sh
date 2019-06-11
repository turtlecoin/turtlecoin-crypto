#!/bin/bash

curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.34.0/install.sh | bash

export NVM_DIR="$HOME/.nvm"

[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" >/dev/null

[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion" >/dev/null

nvm ls-remote >/dev/null

# Test on Node v6

nvm install 6 >/dev/null

nvm use 6

node --version

npm install && npm test

rm -rf node_modules

# Test on Node v8

nvm install 8 >/dev/null

nvm use 8

node --version

npm install && npm test

rm -rf node_modules

# Test on Node v10

nvm install 10 >/dev/null

nvm use 10

node --version

npm install && npm test

rm -rf node_modules

# Test on Node v11

nvm install 11 >/dev/null

nvm use 11

node --version

npm install && npm test

rm -rf node_modules

# Test on Node v11

nvm install latest >/dev/null

nvm use latest

node --version

npm install && npm test

rm -rf node_modules
