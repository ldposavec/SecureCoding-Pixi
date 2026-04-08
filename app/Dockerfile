FROM node:8-alpine
RUN apk add --no-cache make gcc g++ python3 && \
    rm -rf /usr/src/pixi/web/uploads && \
    mkdir -p /usr/src/pixi/web
WORKDIR /usr/src/pixi/web
COPY package.json /usr/src/pixi/web
COPY package-lock.json /usr/src/pixi/web

RUN npm install --save && \
    npm install --save express && \
    npm install --save helmet@3.23.3

COPY . /usr/src/pixi/web
COPY uploads/ /usr/src/pixi/web/uploads/

RUN node /usr/src/pixi/web/updated_libs.js && \
    npm install --unsafe-perm -g nodemon@1.11.0

EXPOSE 8000
CMD ["nodemon", "/usr/src/pixi/web/server.js"]