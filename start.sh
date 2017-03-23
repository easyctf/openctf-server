#!/bin/bash
set -e

COMMAND=$1
DATABASE_URL="mysql://root:$MYSQL_ROOT_PASSWORD@db/$MYSQL_DATABASE"

until mysql -h db -u root -p"$MYSQL_ROOT_PASSWORD"; do
  >&2 echo "mysql is unavailable - sleeping"
  sleep 1
done

>&2 echo "mysql is up - executing command"
if [ "$COMMAND" == "runserver" ]; then
  if [ "$ENV" == "dev" ]; then
    exec bash -c "DATABASE_URL=$DATABASE_URL python manage.py db upgrade && python manage.py runserver"
  else
    exec bash -c "DATABASE_URL=$DATABASE_URL python manage.py db upgrade && gunicorn --bind 0.0.0.0:80 -w 4 app:app"
  fi
elif [ "$COMMAND" == "compute" ]; then
  exec bash -c "DATABASE_URL=$DATABASE_URL python manage.py db upgrade && python manage.py compute worker"
fi