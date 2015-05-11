
test:
	envdir envs/dev/ coverage run --branch --source=mygpoauth ./manage.py test
	coverage report --show-missing

.PHONY: test
