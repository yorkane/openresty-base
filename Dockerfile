# Dockerfile - openresty-base (alpine)
# Custom OpenResty build with extra modules:
#   - lua-nginx-module (main branch)
#   - nginx-dav-ext-module (WebDAV PROPFIND/OPTIONS/LOCK/UNLOCK)
#   - ngx-fancyindex (fancy directory listing)
#
# Reference: https://github.com/openresty/docker-openresty/blob/master/alpine/Dockerfile
#            https://github.com/openresty/docker-openresty/blob/master/alpine/Dockerfile.fat

# --------------------------------------------------------------------------
# Build-time arguments (overridden by GitHub Actions workflow)
# --------------------------------------------------------------------------
ARG RESTY_IMAGE_BASE="alpine"
ARG RESTY_IMAGE_TAG="3.22"

FROM ${RESTY_IMAGE_BASE}:${RESTY_IMAGE_TAG} AS builder

# Keep ARGs available after FROM
ARG RESTY_VERSION="1.29.2.1"
ARG RESTY_OPENSSL_VERSION="3.5.5"
ARG RESTY_OPENSSL_PATCH_VERSION="3.5.5"
ARG RESTY_OPENSSL_URL_BASE="https://github.com/openssl/openssl/releases/download/openssl-${RESTY_OPENSSL_VERSION}"
ARG RESTY_PCRE_VERSION="10.47"
ARG RESTY_PCRE_BUILD_OPTIONS="--enable-jit"
ARG RESTY_PCRE_OPTIONS="--with-pcre-jit"
ARG RESTY_J="4"

# Versions for extra modules (overridden by workflow to pin exact commits/tags)
ARG LUA_NGINX_MODULE_VERSION="main"
ARG NGX_FANCYINDEX_VERSION="master"
ARG NGX_DAV_EXT_VERSION="master"

ARG RESTY_CONFIG_OPTIONS="\
    --with-compat \
    --with-file-aio \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_geoip_module=dynamic \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_image_filter_module=dynamic \
    --with-http_mp4_module \
    --with-http_random_index_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_slice_module \
    --with-http_ssl_module \
    --with-http_stub_status_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-http_xslt_module=dynamic \
    --with-ipv6 \
    --with-mail \
    --with-mail_ssl_module \
    --with-md5-asm \
    --with-sha1-asm \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-threads \
    "

ARG RESTY_CONFIG_OPTIONS_MORE=""
ARG RESTY_LUAJIT_OPTIONS="--with-luajit-xcflags='-DLUAJIT_NUMMODE=2 -DLUAJIT_ENABLE_LUA52COMPAT'"
ARG RESTY_PCRE_OPTIONS="--with-pcre-jit"

ARG RESTY_ADD_PACKAGE_BUILDDEPS=""
ARG RESTY_ADD_PACKAGE_RUNDEPS=""

LABEL maintainer="yorkane"
LABEL resty_version="${RESTY_VERSION}"
LABEL resty_openssl_version="${RESTY_OPENSSL_VERSION}"
LABEL resty_pcre_version="${RESTY_PCRE_VERSION}"
LABEL lua_nginx_module_version="${LUA_NGINX_MODULE_VERSION}"
LABEL ngx_fancyindex_version="${NGX_FANCYINDEX_VERSION}"
LABEL ngx_dav_ext_version="${NGX_DAV_EXT_VERSION}"

# Install build deps
RUN apk add --no-cache --virtual .build-deps \
        build-base \
        coreutils \
        curl \
        gd-dev \
        geoip-dev \
        git \
        libxslt-dev \
        libxml2-dev \
        linux-headers \
        make \
        perl-dev \
        readline-dev \
        zlib-dev \
        ${RESTY_ADD_PACKAGE_BUILDDEPS} \
    && apk add --no-cache \
        gd \
        geoip \
        libgcc \
        libxslt \
        libxml2 \
        zlib \
        ${RESTY_ADD_PACKAGE_RUNDEPS}

# --------------------------------------------------------------------------
# Download & verify OpenSSL
# --------------------------------------------------------------------------
RUN cd /tmp \
    && curl -fSL "${RESTY_OPENSSL_URL_BASE}/openssl-${RESTY_OPENSSL_VERSION}.tar.gz" \
            -o "openssl-${RESTY_OPENSSL_VERSION}.tar.gz" \
    && tar xzf "openssl-${RESTY_OPENSSL_VERSION}.tar.gz"

# --------------------------------------------------------------------------
# Download PCRE2 (source kept for OpenResty --with-pcre reference)
# --------------------------------------------------------------------------
RUN cd /tmp \
    && curl -fSL "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${RESTY_PCRE_VERSION}/pcre2-${RESTY_PCRE_VERSION}.tar.gz" \
            -o "pcre2-${RESTY_PCRE_VERSION}.tar.gz" \
    && tar xzf "pcre2-${RESTY_PCRE_VERSION}.tar.gz" \
    && mv "/tmp/pcre2-${RESTY_PCRE_VERSION}" /tmp/pcre2-src \
    && rm -f "pcre2-${RESTY_PCRE_VERSION}.tar.gz"

# --------------------------------------------------------------------------
# Clone extra modules
# --------------------------------------------------------------------------
# 1. lua-nginx-module (main branch — replaces OpenResty's bundled version)
RUN git clone --depth=1 --branch "${LUA_NGINX_MODULE_VERSION}" \
        https://github.com/openresty/lua-nginx-module.git \
        /tmp/lua-nginx-module

# 2. nginx-dav-ext-module
RUN git clone --depth=1 --branch "${NGX_DAV_EXT_VERSION}" \
        https://github.com/mid1221213/nginx-dav-ext-module.git \
        /tmp/nginx-dav-ext-module

# 3. ngx-fancyindex
RUN git clone --depth=1 --branch "${NGX_FANCYINDEX_VERSION}" \
        https://github.com/aperezdc/ngx-fancyindex.git \
        /tmp/ngx-fancyindex

# --------------------------------------------------------------------------
# Download & build OpenResty (with extra modules)
# --------------------------------------------------------------------------
RUN cd /tmp \
    && curl -fSL "https://openresty.org/download/openresty-${RESTY_VERSION}.tar.gz" \
            -o "openresty-${RESTY_VERSION}.tar.gz" \
    && tar xzf "openresty-${RESTY_VERSION}.tar.gz" \
    && cd "/tmp/openresty-${RESTY_VERSION}" \
    && eval ./configure \
        --prefix=/usr/local/openresty \
        ${RESTY_CONFIG_OPTIONS} \
        ${RESTY_CONFIG_OPTIONS_MORE} \
        ${RESTY_LUAJIT_OPTIONS} \
        ${RESTY_PCRE_OPTIONS} \
        --with-pcre="/tmp/pcre2-src" \
        --with-openssl="/tmp/openssl-${RESTY_OPENSSL_VERSION}" \
        --add-module=/tmp/lua-nginx-module \
        --add-module=/tmp/nginx-dav-ext-module \
        --add-module=/tmp/ngx-fancyindex \
    && make -j${RESTY_J} \
    && make install \
    && cd /tmp \
    && rm -rf \
        "openresty-${RESTY_VERSION}" \
        "openresty-${RESTY_VERSION}.tar.gz" \
        "openssl-${RESTY_OPENSSL_VERSION}" \
        "openssl-${RESTY_OPENSSL_VERSION}.tar.gz" \
        /tmp/pcre2-src \
        /tmp/lua-nginx-module \
        /tmp/nginx-dav-ext-module \
        /tmp/ngx-fancyindex \
    && apk del .build-deps \
    && ln -sf /dev/stdout /usr/local/openresty/nginx/logs/access.log \
    && ln -sf /dev/stderr /usr/local/openresty/nginx/logs/error.log

# --------------------------------------------------------------------------
# Install LuaRocks + envsubst (mirrors Dockerfile.fat)
# --------------------------------------------------------------------------
ARG RESTY_LUAROCKS_VERSION="3.13.0"

RUN apk add --no-cache --virtual .build-deps \
        perl-dev \
    && apk add --no-cache \
        bash \
        build-base \
        curl \
        libintl \
        linux-headers \
        make \
        musl \
        outils-md5 \
        perl \
        unzip \
        wget \
    && cd /tmp \
    && curl -fSL "https://luarocks.github.io/luarocks/releases/luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz" \
            -o "luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz" \
    && tar xzf "luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz" \
    && cd "luarocks-${RESTY_LUAROCKS_VERSION}" \
    && ./configure \
        --prefix=/usr/local/openresty/luajit \
        --with-lua=/usr/local/openresty/luajit \
        --with-lua-include=/usr/local/openresty/luajit/include/luajit-2.1 \
    && make build \
    && make install \
    && cd /tmp \
    && rm -rf "luarocks-${RESTY_LUAROCKS_VERSION}" "luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz" \
    && apk add --no-cache --virtual .gettext gettext \
    && mv /usr/bin/envsubst /tmp/ \
    && apk del .build-deps .gettext \
    && mv /tmp/envsubst /usr/local/bin/

# --------------------------------------------------------------------------
# Runtime environment
# --------------------------------------------------------------------------
ENV PATH="/usr/local/openresty/luajit/bin:/usr/local/openresty/nginx/sbin:/usr/local/openresty/bin:${PATH}"

ENV LUA_PATH="/usr/local/openresty/site/lualib/?.ljbc;/usr/local/openresty/site/lualib/?/init.ljbc;/usr/local/openresty/lualib/?.ljbc;/usr/local/openresty/lualib/?/init.ljbc;/usr/local/openresty/site/lualib/?.lua;/usr/local/openresty/site/lualib/?/init.lua;/usr/local/openresty/lualib/?.lua;/usr/local/openresty/lualib/?/init.lua;./?.lua;/usr/local/openresty/luajit/share/luajit-2.1/?.lua;/usr/local/share/lua/5.1/?.lua;/usr/local/share/lua/5.1/?/init.lua;/usr/local/openresty/luajit/share/lua/5.1/?.lua;/usr/local/openresty/luajit/share/lua/5.1/?/init.lua"

ENV LUA_CPATH="/usr/local/openresty/site/lualib/?.so;/usr/local/openresty/lualib/?.so;./?.so;/usr/local/lib/lua/5.1/?.so;/usr/local/openresty/luajit/lib/lua/5.1/?.so;/usr/local/lib/lua/5.1/loadall.so;/usr/local/openresty/luajit/lib/lua/5.1/?.so"

EXPOSE 80 443

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
