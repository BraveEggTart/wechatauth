FROM python:3.10.4

ARG PIP_TRUSTED_HOST=mirrors.aliyun.com
ARG PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple

RUN pip config set global.trusted-host ${PIP_TRUSTED_HOST}  \
    && pip config set global.index-url ${PIP_INDEX_URL}

WORKDIR /app 

COPY . /app 
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN echo 'Asia/Shanghai' >/etc/timezone

RUN pip3 install -r requirements.txt --no-cache-dir