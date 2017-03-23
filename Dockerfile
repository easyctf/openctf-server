FROM python:2-onbuild

RUN apt-get update
RUN apt-get install -y python-nose libjpeg-dev libffi-dev libssl-dev mysql-client libmysqlclient-dev git

RUN mkdir /openctf
WORKDIR /openctf
COPY . /openctf/

CMD ["gunicorn", "--reload", "--bind", "0.0.0.0:80", "-w", "4", "app:app"]
EXPOSE 80