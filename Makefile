PY=python

install:
	$(PY) -m pip install -r requirements.txt

check:
	$(PY) manage.py check

migrate:
	$(PY) manage.py makemigrations
	$(PY) manage.py migrate

seed:
	$(PY) manage.py seed_data

run:
	$(PY) manage.py runserver
