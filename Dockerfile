FROM python:2-onbuild
EXPOSE 6725
CMD uwsgi --ini wannacry.ini
