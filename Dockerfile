FROM python:3-onbuild

RUN apt-get update
RUN apt-get install -y python-nose libjpeg-dev libffi-dev libssl-dev mysql-client libmysqlclient-dev git

RUN mkdir /openctf
WORKDIR /openctf
COPY . /openctf/

CMD ["bash", "/openctf/start.sh"]
EXPOSE 80
