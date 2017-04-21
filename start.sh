#!/bin/bash
set -e

COMMAND=$1
export DATABASE_URL="mysql://root:$MYSQL_ROOT_PASSWORD@db/$MYSQL_DATABASE"

until mysql -h db -u root -p"$MYSQL_ROOT_PASSWORD"; do
  >&2 echo "mysql is unavailable - sleeping"
  sleep 1
done

>&2 echo "mysql is up at $DATABASE_URL - executing command"
if [ "$COMMAND" == "runserver" ]; then
  if [ "$ENV" == "dev" ]; then
    exec bash -c 'python3 manage.py db upgrade; python3 manage.py runserver'
  else
    exec bash -c 'python3 manage.py db upgrade; gunicorn --bind 0.0.0.0:80 -w 4 "openctf.app:create_app()"'
  fi
# elif [ "$COMMAND" == "compute" ]; then
#   exec bash -c "DATABASE_URL=$DATABASE_URL python3 manage.py db upgrade && python3 manage.py compute worker"
fi
